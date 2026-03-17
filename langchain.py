# ===============================
# 5G Multi-Agent AI QoE Analysis System
# Using LangChain + LangGraph + Ollama
# ===============================

import os
from typing import TypedDict, List
from IPython.display import display, Image

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser

# ===============================
# Step 1: Environment Configuration (Optional LangSmith)
# ===============================
os.environ["LANGCHAIN_TRACING_V2"] = "true"
os.environ["LANGCHAIN_PROJECT"] = "5G-QoE-Lang-Lab"
os.environ["LANGCHAIN_API_KEY"] = "your-api-key-here"  # Replace with your actual key

# ===============================
# Step 2: Define State Structure
# ===============================
class QoEState(TypedDict):
    user_input: str
    kpi_validation: str
    qoe_classification: str
    network_advice: str
    memory: List[str]
    human_approved: bool

# ===============================
# Step 3: Initialize Language Model
# ===============================
llm = ChatOllama(
    model="llama3.1:8b",
    temperature=0
)

# ===============================
# Step 4: Implement KPI Sanity Check Agent
# ===============================
def kpi_sanity_agent(state: QoEState) -> QoEState:
    system_prompt = """
    You are a strict telecom KPI validation agent.

    Your ONLY task:
    - Check whether KPI VALUES are within allowed numeric ranges.
    - Do NOT judge performance quality.
    - Do NOT decide whether values are good or bad.

    Validation rules (strict):
    - RSSI is VALID if between -40 dBm and -140 dBm (inclusive)
    - Latency is VALID if it is a positive number (> 0 ms)
    - Packet loss is VALID if between 0% and 100% (inclusive)
    - Network type must be exactly one of: 4G, 5G NSA, 5G SA

    Output format (STRICT):
    VALID or INVALID
    One-line reason ONLY if INVALID.
    """

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=state["user_input"])
    ]

    response = llm.invoke(messages)

    return {
        "user_input": state["user_input"],
        "kpi_validation": response.content
    }

# ===============================
# Step 5: Implement QoE Classification Agent (Few-Shot Learning)
# ===============================
qoe_prompt_lcel = ChatPromptTemplate.from_messages([
    ("system", """
    You are a telecom Quality of Experience (QoE) classification agent.

    Your task: Classify user experience into exactly ONE of the following labels:
    Smooth, Acceptable, Poor

    Base your decision ONLY on:
    - Latency (ms)
    - Packet loss (%)

    Do NOT validate data. Do NOT give network advice. Do NOT invent new labels.

    Few-Shot Examples:
    Example 1: Latency: 8 ms, Packet Loss: 0.2 % → QoE: Smooth
    Example 2: Latency: 15 ms, Packet Loss: 0.5 % → QoE: Smooth
    Example 3: Latency: 25 ms, Packet Loss: 0.9 % → QoE: Smooth
    Example 4: Latency: 35 ms, Packet Loss: 1.2 % → QoE: Acceptable
    Example 5: Latency: 80 ms, Packet Loss: 2.5 % → QoE: Poor
    """),
    ("human", "{user_input}")
])

qoe_chain_lcel = qoe_prompt_lcel | llm | StrOutputParser()

def qoe_classification_agent(state: QoEState) -> QoEState:
    qoe_result = qoe_chain_lcel.invoke({"user_input": state["user_input"]})
    return {
        "user_input": state["user_input"],
        "kpi_validation": state["kpi_validation"],
        "qoe_classification": qoe_result
    }

# ===============================
# Step 6: Implement Network Advice Agent
# ===============================
def network_advice_agent(state: QoEState) -> QoEState:
    system_prompt = """
    You are a telecom network advisory agent.

    Your task:
    Provide short, clear advice to the user based on QoE classification.

    Use simple language, as if speaking to a non-expert user.

    Rules:
    - If QoE is Smooth → reassure the user.
    - If QoE is Acceptable → suggest minor improvements.
    - If QoE is Poor → suggest clear corrective actions.

    Do NOT:
    - Reclassify QoE
    - Validate KPIs
    - Mention internal reasoning or few-shot examples

    Advice examples:
    Suggest changing location, switching network mode, checking congestion, or contacting the operator when appropriate.
    """

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"""
        User KPIs:
        {state['user_input']}

        QoE Classification:
        {state['qoe_classification']}
        """)
    ]

    response = llm.invoke(messages)

    return {
        "user_input": state["user_input"],
        "kpi_validation": state["kpi_validation"],
        "qoe_classification": state["qoe_classification"],
        "network_advice": response.content
    }

# ===============================
# Step 7: Implement Human Review Agent (Auto-approve by default)
# ===============================
def human_review(state: QoEState) -> QoEState:
    # For this lab, auto-approve. In production, pause for real human input.
    state["human_approved"] = True
    return state

def route_after_review(state: QoEState) -> str:
    if state["human_approved"]:
        return "approved"
    else:
        return "rejected"

# ===============================
# Step 8: Implement Memory Agent
# ===============================
def memory_agent(state: QoEState) -> QoEState:
    summary = f"QoE: {state['qoe_classification']} Advice: {state['network_advice']}"
    updated_memory = state.get("memory", []) + [summary.strip()]
    return {**state, "memory": updated_memory}

# ===============================
# Step 9: Build LangGraph Workflow
# ===============================
workflow = StateGraph(QoEState)

# Add all nodes
workflow.add_node("kpi_sanity_check", kpi_sanity_agent)
workflow.add_node("qoe_classification", qoe_classification_agent)
workflow.add_node("human_review", human_review)
workflow.add_node("network_advice", network_advice_agent)
workflow.add_node("memory_update", memory_agent)

# Define sequential flow
workflow.add_edge(START, "kpi_sanity_check")
workflow.add_edge("kpi_sanity_check", "qoe_classification")
workflow.add_edge("qoe_classification", "human_review")

# Conditional branching after human review
workflow.add_conditional_edges(
    "human_review",
    route_after_review,
    {
        "approved": "network_advice",
        "rejected": END
    }
)

workflow.add_edge("network_advice", "memory_update")
workflow.add_edge("memory_update", END)

# Compile the graph
app = workflow.compile()

# ===============================
# Step 10: Visualize the Workflow
# ===============================
print("✅ Workflow compiled successfully.")
try:
    display(Image(app.get_graph().draw_mermaid_png()))
except Exception as e:
    print("⚠️ Could not display graph. You can view it in LangSmith.")

# ===============================
# Step 11: Create Output Formatter
# ===============================
def format_result(state: QoEState) -> str:
    output = f"""
    📡 5G NETWORK QUALITY ANALYSIS REPORT
    {'='*50}
    KPI SANITY CHECK: {state.get('kpi_validation', 'N/A')}
    QoE CLASSIFICATION: {state.get('qoe_classification', 'N/A')}
    
    💡 NETWORK ADVICE:
    {state.get('network_advice', 'N/A')}
    
    🧠 MEMORY (Last Entry):
    {state.get('memory', [])[-1] if state.get('memory') else 'Empty'}
    """
    return output

# ===============================
# Step 12: Run the System
# ===============================
def run_system(user_input: str):
    initial_state = {
        "user_input": user_input,
        "kpi_validation": "",
        "qoe_classification": "",
        "network_advice": "",
        "memory": [],
        "human_approved": False
    }
    
    final_state = app.invoke(initial_state)
    print(format_result(final_state))

# ===============================
# Example Execution
# ===============================
print("\n🔍 Running system with example input...\n")
example_input = "RSSI: -95 dBm, Latency: 180 ms, Packet Loss: 4.5 %, Network Type: 5G NSA"
run_system(example_input)

print("\n✅ System execution completed. Check LangSmith for detailed traces.")