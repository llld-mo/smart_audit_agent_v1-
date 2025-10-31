# utils.py
# Pydantic 结构定义、工具定义
from pydantic import BaseModel, Field
from typing import TypedDict, List
import json

# --- LangGraph 状态定义 ---
# 整个图的状态，所有节点共享和更新
class AuditState(TypedDict):
    contract_code: str
    initial_analysis: str
    vulnerability_findings: List[dict] # [{type: str, severity: str, line: int, desc: str}]
    final_report: str
    needs_recheck: bool # 用于控制循环

# --- Pydantic 结构化输出定义 ---
# 确保漏洞检测代理 (Agent B) 给出结构化的结果
class VulnerabilityFinding(BaseModel):
    """一个识别出的潜在智能合约漏洞的结构化表示。"""
    vulnerability_type: str = Field(description="漏洞的类型，例如：Reentrancy, Integer Overflow, Access Control.")
    severity: str = Field(description="严重程度：High, Medium, Low, Informational.")
    code_line: int = Field(description="漏洞出现的大致行号。")
    description: str = Field(description="漏洞的简短描述和潜在影响。")
    
class AnalysisResult(BaseModel):
    """漏洞检测代理的最终结构化输出。"""
    findings: List[VulnerabilityFinding] = Field(description="检测到的所有漏洞列表。")
    recheck_needed: bool = Field(description="如果分析师认为可能存在未发现的严重问题，则为True。")
    
# --- 外部工具定义（LangChain Tool） ---
# 这是一个可选的静态分析工具，这里我们用一个模拟函数代替
def run_static_analysis(code_snippet: str) -> str:
    """
    模拟运行一个轻量级的Solidity静态分析工具，并返回结果。
    在实际项目中，这里会调用Mythril或Slither的API或命令行。
    """
    print("-> 正在运行模拟静态分析工具...")
    # 模拟工具输出
    if "call.value" in code_snippet or "send(" in code_snippet:
        return "Warning: Possible low-level call or Ether transfer detected. Check for reentrancy."
    return "No obvious warnings from static tool."

# 工具列表
TOOLS = [run_static_analysis]