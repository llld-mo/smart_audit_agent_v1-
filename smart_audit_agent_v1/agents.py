# agents.py
# 代理/节点函数定义 (A, B, C)
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser
from langchain_core.runnables import RunnablePassthrough
from typing import Literal
from utils import AuditState, AnalysisResult, run_static_analysis, TOOLS
import os

# 确保设置了OpenAI API Key
# os.environ["OPENAI_API_KEY"] = "YOUR_API_KEY"

# 使用一个固定的模型
MODEL = ChatOpenAI(
    model="deepseek-ai/DeepSeek-R1-0528-Qwen3-8B",  
    openai_api_key="sk-cvamswnmgapnlfeymnmjszhdgoibpevkpdzgrteqnebamdbj",
    openai_api_base="https://api.siliconflow.cn/v1" 
    )

# --- A. 初步分析节点 ---
def initial_analysis_node(state: AuditState) -> AuditState:
    """
    代理A：分析合约代码，理解其功能和核心逻辑。
    """
    print("--- A. 正在进行初步分析 ---")
    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一名高级智能合约项目经理。你的任务是总结提供的Solidity合约代码的功能、目的和核心逻辑（例如：这是一个代币合约、一个投票系统、还是一个质押合约）。"),
        ("user", "请分析以下合约代码，并用中文总结:\n\n{code}")
    ])
    
    chain = prompt | MODEL | JsonOutputParser() # 这里使用通用Parser，输出只是总结
    
    analysis_result = chain.invoke({"code": state["contract_code"]})
    
    # 假设 LLM 输出的是一个包含总结的字符串
    summary = analysis_result.get('summary', str(analysis_result)) if isinstance(analysis_result, dict) else str(analysis_result)

    return {"initial_analysis": summary}


# --- B. 漏洞检测节点 ---
def vulnerability_detection_node(state: AuditState) -> AuditState:
    """
    代理B：专注于使用专业知识和工具检测漏洞。
    """
    print("--- B. 正在进行漏洞检测 ---")
    
    # 1. 运行外部工具（静态分析）
    tool_output = run_static_analysis(state["contract_code"])
    
    # 2. 结合初步分析和工具结果，进行深度LLM分析
    prompt_template = ChatPromptTemplate.from_messages([
        ("system", "你是一名专业的智能合约安全审计专家。你的任务是仔细审查提供的Solidity代码，并查找如重入、整数溢出、访问控制、Tx Origin等常见漏洞。你必须使用提供的格式输出。"),
        ("system", f"合约概述: {state['initial_analysis']}"),
        ("system", f"静态分析工具警告: {tool_output}"),
        ("user", "请对以下代码进行安全审计，并以JSON格式严格输出。如果发现任何值得注意的潜在问题，请将`recheck_needed`设为True。\n\n代码:\n{code}")
    ])
    
    parser = JsonOutputParser(pydantic_object=AnalysisResult)
    chain = (
        prompt_template 
        | MODEL.with_structured_output(AnalysisResult) 
    )

    result_obj = chain.invoke({"code": state["contract_code"]})
    
    # 将Pydantic对象转换为dict列表，以便更新状态
    findings = [f.dict() for f in result_obj.findings]
    
    return {
        "vulnerability_findings": findings,
        "needs_recheck": result_obj.recheck_needed # B代理决定是否需要校验代理再次介入
    }


# --- C. 报告生成与校验节点 ---
def report_generation_node(state: AuditState) -> AuditState:
    """
    代理C：结构化整理发现，生成最终报告。
    """
    print("--- C. 正在生成最终报告 ---")
    
    # 将发现列表转换为易于LLM处理的字符串
    findings_str = ""
    for idx, f in enumerate(state["vulnerability_findings"]):
        findings_str += f"- 发现 {idx+1}: {f['vulnerability_type']} (严重性: {f['severity']})\n  行号: {f['code_line']}\n  描述: {f['description']}\n---\n"
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", "你是一名专业的安全报告撰写员。你的任务是结构化整理提供的审计发现，生成一份专业的审计报告。报告必须包含：总结、发现列表（类型、严重性、行号）、以及专业的修复建议。"),
        ("system", f"合约概述: {state['initial_analysis']}"),
        ("user", f"请根据以下发现列表生成一份专业的中文审计报告:\n\n发现列表:\n{findings_str}")
    ])
    
    chain = prompt | MODEL
    final_report = chain.invoke({}) # 不传入user输入，只依赖上下文
    
    return {"final_report": final_report.content, "needs_recheck": False} # 结束循环

# --- 路由函数 ---
def should_continue(state: AuditState) -> Literal["report_generation", "__end__"]:
    """
    根据 Agent B 的判断和发现数量，决定是否继续进行。
    在项目一中，我们简化为：如果发现有任何内容，就进入报告。
    """
    if state.get("needs_recheck") or state.get("vulnerability_findings"):
        print("-> 检测到潜在问题或需要复查，路由到报告生成...")
        return "report_generation"
    else:
        print("-> 未发现任何值得报告的问题，流程结束。")
        return "__end__"