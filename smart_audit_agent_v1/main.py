# main.py
# 核心 LangGraph 流程定义和执行

from langgraph.graph import StateGraph, END
from agents import initial_analysis_node, vulnerability_detection_node, report_generation_node, should_continue
from utils import AuditState

# 示例智能合约代码 (一个简单的、有已知漏洞的合约)
SAMPLE_CONTRACT_CODE = """
pragma solidity ^0.8.0;

contract VulnerableContract {
    mapping (address => uint256) public balances;

    constructor() {
        balances[msg.sender] = 100 ether;
    }
    
    // 潜在的重入漏洞
    function withdraw(uint256 amount) public {
        require(balances[msg.sender] >= amount, "Insufficient balance");
        
        balances[msg.sender] -= amount; // 余额更新在外部调用之前
        
        (bool success, ) = msg.sender.call{value: amount}(""); // 外部调用
        require(success, "Transfer failed");
        
        // 余额更新应该在这里：balances[msg.sender] -= amount; 
    }
}
"""

def build_and_run_graph(contract_code: str):
    """
    构建 LangGraph 并执行审计流程。
    """
    # 1. 定义图的结构
    workflow = StateGraph(AuditState)

    # 2. 添加节点
    workflow.add_node("initial_analysis", initial_analysis_node)
    workflow.add_node("vulnerability_detection", vulnerability_detection_node)
    workflow.add_node("report_generation", report_generation_node)

    # 3. 设置边和流程
    workflow.set_entry_point("initial_analysis")

    # A -> B
    workflow.add_edge("initial_analysis", "vulnerability_detection")
    
    # B -> 路由函数
    workflow.add_conditional_edges(
        "vulnerability_detection", # 源节点
        should_continue,          # 路由函数
        {
            "report_generation": "report_generation", # 如果有发现/需要复查，进入报告生成
            "__end__": END                            # 如果没有发现，直接结束
        }
    )
    
    # C -> END (项目一的简化：报告完成后即结束)
    workflow.add_edge("report_generation", END)

    # 4. 编译和运行
    app = workflow.compile()
    
    # 初始状态
    inputs = {"contract_code": contract_code}
    
    print("================ 审计流程开始 ================")
    
    # 运行图并获取最终状态
    final_state = app.invoke(inputs)

    print("\n================ 审计流程结束 ================")
    print("\n--- 最终审计报告 ---")
    print(final_state["final_report"])
    
if __name__ == "__main__":
    # 您可以将 SAMPLE_CONTRACT_CODE 替换为您想审计的任何 Solidity 合约
    build_and_run_graph(SAMPLE_CONTRACT_CODE)