# agents.py
# 代理/节点函数定义 (A, B, C)
from langchain_core.prompts import ChatPromptTemplate
from langchain_openai import ChatOpenAI
from langchain_core.output_parsers import JsonOutputParser,StrOutputParser
from langchain_core.runnables import RunnablePassthrough
from typing import Literal
from utils import AuditState, AnalysisResult, run_static_analysis, TOOLS
from langchain_core.messages import SystemMessage, HumanMessage
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
    
    chain = prompt | MODEL | StrOutputParser() # 这里使用通用Parser，输出只是总结
    
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
    
    # 2. 手动构建消息列表，避免 PromptTemplate 解析冲突
    
    # System Message 1: 角色定义和指令
    system_message_role = SystemMessage(
        content="你是一名专业的智能合约安全审计专家。你的任务是仔细审查提供的Solidity代码，并查找如重入、整数溢出、访问控制、Tx Origin等常见漏洞。你**必须**使用提供的结构化格式输出。"
    )
    
    # System Message 2: 审计上下文信息
    system_message_context = SystemMessage(
        content=(
            f"合约概述: {state['initial_analysis']}\n"
            f"静态分析工具警告: {tool_output}"
        )
    )
    
    # User Message: 提交代码
    user_message = HumanMessage(
        content=f"请对以下代码进行安全审计，并以JSON格式严格输出。如果发现任何值得注意的潜在问题，请将`recheck_needed`设为True。\n\n代码:\n{state['contract_code']}"
    )

    messages = [system_message_role, system_message_context, user_message]
    
    # 3. 使用 with_structured_output 创建 Chain
    # LLM 接收的是消息列表，不再是 Prompt Template
    chain = MODEL.with_structured_output(AnalysisResult) 

    # 4. 直接调用 Chain，传入消息列表
    # 由于 messages 已经包含了所有信息，我们不需要传入额外的输入字典
    result_obj: AnalysisResult = chain.invoke(messages)
    
    # 5. 更新状态
    # 确保使用 Pydantic V2 的 model_dump()
    findings = [f.model_dump() for f in result_obj.findings]
    
    return {
        "vulnerability_findings": findings,
        "needs_recheck": result_obj.recheck_needed
    }


# --- C. 报告生成与校验节点 ---
def report_generation_node(state: AuditState) -> AuditState:
    """
    代理C：整合所有信息，生成最终的审计报告。
    """
    print("--- C. 正在生成最终报告 ---")
    
    # 1. 格式化漏洞发现，使其易于阅读
    findings_str = "\n".join([
        # 使用 .get() 安全访问字典键
        f"--- 漏洞名称: {f.get('name', 'N/A')} (严重性: {f.get('severity', 'N/A')}) ---\n"
        f"描述: {f.get('description', 'N/A')}\n"
        f"建议: {f.get('recommendation', 'N/A')}\n"
        # 增加一个检查，确保 f 确实是字典
        for f in state["vulnerability_findings"] if isinstance(f, dict)
    ])
    
    if not findings_str:
        findings_str = "未发现任何高风险漏洞。"

    # 2. 手动构建消息列表，彻底避免 PromptTemplate 变量解析冲突
    system_message_role = SystemMessage(
        content="你是一名专业的安全审计报告撰写人。请基于提供的代码和审计发现，生成一份专业、结构化的智能合约审计报告。报告必须包含：概述、审计范围、审计发现详情（如果有）、结论。使用Markdown格式，并保持语言专业严谨。"
    )
    
    # 将所有上下文信息打包到 HumanMessage 中
    user_message = HumanMessage(
        content=(
            "请基于以下上下文生成最终审计报告：\n\n"
            f"原始合约代码:\n```solidity\n{state['contract_code']}\n```\n\n"
            f"初步分析:\n{state['initial_analysis']}\n\n"
            f"审计发现:\n{findings_str}"
        )
    )

    messages = [system_message_role, user_message]
    
    # 3. 创建 Chain (这里不需要结构化输出，只需要纯文本)
    chain = MODEL
    
    # 4. 调用 Chain，传入消息列表。
    final_report = chain.invoke(messages).content
    
    return {
        "final_report": final_report
    }

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