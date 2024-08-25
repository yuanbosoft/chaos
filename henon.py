import numpy as np
import matplotlib.pyplot as plt
from scipy.integrate import solve_ivp

# 1. 固定点吸引子（Fixed Point Attractor）
def fixed_point_attractor(t, y):
    return -0.5 * y  # 简单的阻尼系统

# 2. 极限环吸引子（Limit Cycle Attractor）
def limit_cycle_attractor(t, y):
    x, y = y
    dx_dt = y
    dy_dt = -x + (1 - x**2) * y  # 范德波尔振子方程
    return [dx_dt, dy_dt]

# 3. 环面吸引子（Torus Attractor）
def torus_attractor(t, y, omega1=1.0, omega2=1.0):
    theta1, theta2 = y
    dtheta1_dt = omega1
    dtheta2_dt = omega2
    return [dtheta1_dt, dtheta2_dt]

# 4. 混沌吸引子（Chaotic Attractor） - 洛伦兹吸引子
def lorenz_attractor(t, y, sigma=10.0, rho=28.0, beta=8.0/3.0):
    x, y, z = y
    dx_dt = sigma * (y - x)
    dy_dt = x * (rho - z) - y
    dz_dt = x * y - beta * z
    return [dx_dt, dy_dt, dz_dt]

# 5. 奇异吸引子（Strange Attractor） - 罗斯勒吸引子
def rossler_attractor(t, y, a=0.2, b=0.2, c=5.7):
    x, y, z = y
    dx_dt = -y - z
    dy_dt = x + a * y
    dz_dt = b + z * (x - c)
    return [dx_dt, dy_dt, dz_dt]

# 6. Duffing 振子（Duffing Oscillator）
def duffing_oscillator(t, y, alpha=1.0, beta=-1.0, delta=0.2, gamma=0.3, omega=1.2):
    x, y = y
    dx_dt = y
    dy_dt = -delta * y - alpha * x - beta * x**3 + gamma * np.cos(omega * t)
    return [dx_dt, dy_dt]

# 7. Henon 吸引子（Henon Attractor）
def henon_map(a=1.4, b=0.3, n=10000):
    x = np.zeros(n)
    y = np.zeros(n)
    x[0], y[0] = 0.1, 0.3
    for i in range(1, n):
        x[i] = 1 - a * x[i-1]**2 + y[i-1]
        y[i] = b * x[i-1]
    return x, y

# 8. Logistic Map
def logistic_map(r=3.8, x0=0.1, n=1000):
    x = np.zeros(n)
    x[0] = x0
    for i in range(1, n):
        x[i] = r * x[i-1] * (1 - x[i-1])
    return np.arange(n), x

# 数值求解和绘图
fig, axs = plt.subplots(3, 3, figsize=(15, 15), dpi=150)
time_span = np.linspace(0, 50, 5000)  # 统一t_span和t_eval的范围

# 1. 固定点吸引子
sol = solve_ivp(fixed_point_attractor, [0, 50], [10], t_eval=time_span)
axs[0, 0].plot(time_span, sol.y[0], lw=2, color="darkblue")
axs[0, 0].set_title("Fixed Point Attractor")

# 2. 极限环吸引子
sol = solve_ivp(limit_cycle_attractor, [0, 50], [1, 0], t_eval=time_span)
axs[0, 1].plot(sol.y[0], sol.y[1], lw=2, color="darkgreen")
axs[0, 1].set_title("Limit Cycle Attractor")

# 3. 环面吸引子
theta1 = time_span * 0.2
theta2 = time_span * 0.5
axs[0, 2].plot(np.cos(theta1), np.sin(theta1), lw=2, color="darkred", label="Theta1")
axs[0, 2].plot(np.cos(theta2), np.sin(theta2), lw=2, color="orange", label="Theta2")
axs[0, 2].set_title("Torus Attractor")
axs[0, 2].legend()

# 4. 混沌吸引子 - 洛伦兹吸引子
sol = solve_ivp(lorenz_attractor, [0, 50], [1, 1, 1], t_eval=time_span)
axs[1, 0] = fig.add_subplot(3, 3, 4, projection='3d')
axs[1, 0].plot(sol.y[0], sol.y[1], sol.y[2], lw=0.5, color="purple")
axs[1, 0].set_title("Lorenz Attractor (Chaotic)")

# 5. 奇异吸引子 - 罗斯勒吸引子
sol = solve_ivp(rossler_attractor, [0, 50], [1, 1, 1], t_eval=time_span)
axs[1, 1] = fig.add_subplot(3, 3, 5, projection='3d')
axs[1, 1].plot(sol.y[0], sol.y[1], sol.y[2], lw=0.5, color="black")
axs[1, 1].set_title("Rossler Attractor (Strange)")

# 6. Duffing 振子
sol = solve_ivp(duffing_oscillator, [0, 50], [0.1, 0], t_eval=time_span)
axs[1, 2].plot(sol.y[0], sol.y[1], lw=2, color="brown")
axs[1, 2].set_title("Duffing Oscillator")

# 7. Henon 吸引子
x, y = henon_map()
axs[2, 0].plot(x, y, lw=0.5, color="darkorange")
axs[2, 0].set_title("Henon Attractor")

# 8. Logistic Map
n, x = logistic_map()
axs[2, 1].plot(n, x, lw=2, color="teal")
axs[2, 1].set_title("Logistic Map")

# 隐藏多余的子图
axs[2, 2].axis('off')

plt.tight_layout()
plt.show()
