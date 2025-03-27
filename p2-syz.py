import matplotlib.pyplot as plt
import networkx as nx
from matplotlib.patches import FancyBboxPatch

plt.rcParams['font.sans-serif'] = ['SimHei']  # 中文显示
plt.rcParams['axes.unicode_minus'] = False

# 创建有向图
G = nx.DiGraph()

# 添加节点和边
nodes = [
    (r'$\mathcal{D}$', {'pos': (0.3, 0.7), 'color': '#FFE4C4'}),
    (r'$\mathcal{I}$', {'pos': (0.7, 0.7), 'color': '#DDA0DD'}),
    (r'$\mathcal{T}$', {'pos': (0.3, 0.3), 'color': '#AFEEEE'}),
    (r'$\mathcal{S}$', {'pos': (0.7, 0.3), 'color': '#98FB98'})
]

edges = [
    (nodes[0][0], nodes[1][0], {'label': r'$N \geq 3f+1$', 'offset': (0, 0.05)}),
    (nodes[1][0], nodes[3][0], {'label': r'$H(\cdot)$', 'offset': (0.1, 0)}),
    (nodes[2][0], nodes[1][0], {'label': r'$\pi$', 'offset': (0.05, 0.05)}),
    (nodes[3][0], nodes[0][0], {'label': r'$\text{negl}(n)$', 'offset': (-0.1, 0.01)}),
    (nodes[3][0], nodes[2][0], {'label': r'$\text{Adv} \leq \varepsilon$', 'offset': (0, -0.05)})
]

for node in nodes:
    G.add_node(node[0], **node[1])
for edge in edges:
    G.add_edge(edge[0], edge[1], **edge[2])

# 绘制图形
fig, ax = plt.subplots(figsize=(4, 3))
ax.set_xlim(0, 1)
ax.set_ylim(0, 1)
ax.axis('off')

# 绘制节点
for node in nodes:
    text, attr = node
    x, y = attr['pos']
    
    # 绘制圆角矩形节点
    box = FancyBboxPatch(
        (x-0.15, y-0.08), 0.3, 0.16,
        boxstyle="round,pad=0.03,rounding_size=0.05",
        ec="black", fc=attr['color'], lw=1.5
    )
    ax.add_patch(box)
    
    # 添加文本
    ax.text(x, y, text, ha='center', va='center', 
            fontsize=12, weight='bold')

# 绘制边和标签
for edge in edges:
    start = G.nodes[edge[0]]['pos']
    end = G.nodes[edge[1]]['pos']
    
    # 绘制箭头
    ax.annotate("",
                xy=end, xycoords='data',
                xytext=start, textcoords='data',
                arrowprops=dict(
                    arrowstyle="->",
                    color="#2F4F4F",
                    lw=1.5,
                    shrinkA=15, shrinkB=15,
                    connectionstyle="arc3,rad=0.2" if edge[2]['label'] == r'$\pi$' else None
                ))
    
    # 添加标签
    label_x = (start[0] + end[0])/2 + edge[2]['offset'][0]
    label_y = (start[1] + end[1])/2 + edge[2]['offset'][1]
    
    ax.text(label_x, label_y, edge[2]['label'],
            ha='center', va='center',
            fontsize=10, color='#2F4F4F',
            bbox=dict(boxstyle="round,pad=0.2", 
                     fc="white", ec="none", alpha=0.8))

# 添加标题
ax.text(0.5, 0.95, "区块链核心特征四元组依赖关系", 
        ha='center', va='center', 
        fontsize=14, weight='bold')

plt.show()
plt.close()
