"""
agent — scripted "coding assistant" that executes tool directives from
plain-text task files.

Real-world analog: an LLM-powered coding assistant with cloud access. The
important property of this component is that it obediently executes whatever
tool calls the prompt contains — it does not try to decide for itself whether
a task is legitimate. That decision has to live elsewhere (allowlists,
policies, the observer module built in step 4).
"""
