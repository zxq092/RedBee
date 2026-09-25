"""自研渗透智能体（RedBee）— 单一引擎。

全部派发走 RedBee Agent。
Run 逻辑见 pi_meta/real_dispatch._inhouse_run -> agents/executor.InhouseAgent
"""

# AGENT_META：编排层只暴露自研 RedBee
AGENT_META = {
    "RedBee": {"focus": "webapp",
               "desc": "自研渗透智能体（内置知识库 + 经验回流闭环）"},
}
