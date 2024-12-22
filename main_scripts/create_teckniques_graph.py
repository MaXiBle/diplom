import networkx as nx
import matplotlib.pyplot as plt

# Переписываем код для использования заданных входных данных

# Граф для комплексной атаки, включающей все тактики
G = nx.DiGraph()

# Добавляем узлы и связи на основе входных данных
edges = [
    # Initial Access
    ("Phishing", "Command and Scripting Interpreter", {"label": "User opens phishing link"}),
    ("Exploit Public-Facing Application", "Command and Scripting Interpreter", {"label": "Exploit executed"}),

    # Execution
    ("Command and Scripting Interpreter", "Create or Modify System Process", {"label": "Persistent service created"}),

    # Persistence
    ("Create or Modify System Process", "Valid Accounts", {"label": "Service escalates privileges"}),

    # Privilege Escalation
    ("Valid Accounts", "Obfuscated Files or Information", {"label": "Access to protected resources"}),
    ("Valid Accounts", "Masquerading", {"label": "Disguise malicious processes"}),

    # Defense Evasion
    ("Obfuscated Files or Information", "Credential Dumping", {"label": "Dump credentials"}),
    ("Masquerading", "Credential Dumping", {"label": "Access LSASS"}),

    # Credential Access
    ("Credential Dumping", "System Network Connections Discovery", {"label": "Credentials discovered"}),
    ("Credential Dumping", "File and Directory Discovery", {"label": "Access sensitive files"}),

    # Discovery
    ("System Network Connections Discovery", "Pass the Hash", {"label": "Network path identified"}),
    ("File and Directory Discovery", "Pass the Hash", {"label": "Sensitive files found"}),

    # Lateral Movement
    ("Pass the Hash", "Email Collection", {"label": "Move to another system"}),

    # Collection
    ("Email Collection", "Exfiltration Over Web Service", {"label": "Data collected"}),

    # Exfiltration
    ("Exfiltration Over Web Service", "Data Encrypted for Impact", {"label": "Data exfiltrated"}),

    # Impact
    ("Data Encrypted for Impact", "End", {"label": "System compromised"})
]

# Добавляем все ребра в граф
for edge in edges:
    G.add_edge(edge[0], edge[1], **edge[2])

# Настройка визуализации
pos = nx.spring_layout(G)  # Расположение узлов
nx.draw(G, pos, with_labels=True, node_color="skyblue", node_size=3000, font_size=10)
nx.draw_networkx_edge_labels(G, pos, edge_labels=nx.get_edge_attributes(G, "label"), font_color="red")

# Добавление заголовка
plt.title("Complex Attack Graph")
plt.show()