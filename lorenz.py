import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import matplotlib.font_manager as fm

# 设置全局字体为支持中文的字体，例如 SimHei
plt.rcParams['font.sans-serif'] = ['SimHei']  # 或 'Arial Unicode MS'
plt.rcParams['axes.unicode_minus'] = False  # 正常显示负号

# 定义洛伦兹方程的参数
sigma = 10.0
rho = 28.0
beta = 8.0 / 3.0

# 定义洛伦兹方程
def lorenz(x, y, z, sigma, rho, beta):
    dx_dt = sigma * (y - x)
    dy_dt = x * (rho - z) - y
    dz_dt = x * y - beta * z
    return dx_dt, dy_dt, dz_dt

# 设置初始条件
dt = 0.01
num_steps = 10000

xs = np.empty(num_steps + 1)
ys = np.empty(num_steps + 1)
zs = np.empty(num_steps + 1)

xs[0], ys[0], zs[0] = (0.0, 1.0, 1.05)

# 使用Euler方法求解微分方程
for i in range(num_steps):
    dx_dt, dy_dt, dz_dt = lorenz(xs[i], ys[i], zs[i], sigma, rho, beta)
    xs[i + 1] = xs[i] + (dx_dt * dt)
    ys[i + 1] = ys[i] + (dy_dt * dt)
    zs[i + 1] = zs[i] + (dz_dt * dt)

# 绘制洛伦兹吸引子
fig = plt.figure(figsize=(10, 7))
ax = fig.add_subplot(111, projection='3d')
ax.plot(xs, ys, zs, lw=0.5)
ax.set_xlabel("X Axis")
ax.set_ylabel("Y Axis")
ax.set_zlabel("Z Axis")

# 设置标题，确保中文正常显示
ax.set_title("Lorenz Attractor (洛伦兹吸引子)")

plt.show()
