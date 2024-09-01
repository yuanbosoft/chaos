import numpy as np
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation

# 洛伦兹方程参数
sigma = 10.0
rho = 28.0
beta = 8.0 / 3.0

# 定义洛伦兹方程
def lorenz(X, Y, Z, sigma, rho, beta):
    dX = sigma * (Y - X)
    dY = X * (rho - Z) - Y
    dZ = X * Y - beta * Z
    return dX, dY, dZ

# 初始条件
dt = 0.01
num_steps = 2000  # 减少总帧数以加快速度
X = np.empty(num_steps + 1)
Y = np.empty(num_steps + 1)
Z = np.empty(num_steps + 1)

# 设置初始值
X[0], Y[0], Z[0] = 0., 1., 1.05

# 使用Euler方法迭代洛伦兹方程
for i in range(num_steps):
    dX, dY, dZ = lorenz(X[i], Y[i], Z[i], sigma, rho, beta)
    X[i + 1] = X[i] + (dX * dt)
    Y[i + 1] = Y[i] + (dY * dt)
    Z[i + 1] = Z[i] + (dZ * dt)

# 创建图形
fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(projection='3d')
ax.set_xlim(-20, 20)
ax.set_ylim(-30, 30)
ax.set_zlim(0, 50)
ax.set_title('Dynamic Lorenz Attractor')

line, = ax.plot([], [], [], lw=0.5)

# 初始化函数
def init():
    line.set_data([], [])
    line.set_3d_properties([])
    return line,

# 更新函数
def update(frame):
    line.set_data(X[:frame], Y[:frame])
    line.set_3d_properties(Z[:frame])
    return line,

# 创建动画
anim = FuncAnimation(fig, update, frames=len(X), init_func=init, blit=True, interval=5)  # 调整interval参数加快速度

# 保存为GIF文件
anim.save('lorenz_attractor_fast.gif', writer='pillow', fps=100)  # 调整fps以加快动画速度

plt.show()
