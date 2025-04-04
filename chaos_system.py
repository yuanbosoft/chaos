import numpy as np
from scipy.integrate import solve_ivp
import matplotlib.pyplot as plt
import hashlib

# 系统参数配置
σ, α = 10, 0.1
ρ, β = 28, 8/3
γ, δ, ε = 0.1, 10, 0.1
τ = 1.0
nonce = b'\x12\x34'

# 哈希转换函数
def hash_to_float(data, bits=32):
    h = hashlib.shake_256(data).digest(bits//8)
    return int.from_bytes(h, 'big') / (1 << bits)

# 哈希函数定义
def hash_x(t):
    e_t = int(t * 1000).to_bytes(4, 'big')
    input_data = bytes([a ^ b for a, b in zip(e_t, nonce)])
    return hashlib.sha256(input_data).digest()

def hash_y(w):
    return hashlib.sha256(np.float64(w).tobytes()).digest()

def hash_z(t):
    t_mod = int(t % τ).to_bytes(4, 'big')
    return hashlib.shake_256(t_mod).digest(32)

def hash_w(x,y,z):
    return hashlib.sha3_256(b''.join(
        [np.float64(v).tobytes() for v in [x,y,z]])).digest()

# 微分方程定义
def chaos_system(t, state):
    x, y, z, w = state
    h_x = hash_to_float(hash_x(t)) * 2 - 1
    h_y = hash_to_float(hash_y(w)) * 2 - 1
    h_z = hash_to_float(hash_z(t)) * 2 - 1
    h_w = hash_to_float(hash_w(x,y,z)) * 2 - 1
    
    return [
        σ*(y - x) + α * h_x,
        x*(ρ - z) - y + β * h_y,
        x*y - β*z + γ * h_z,
        -δ*w + ε * h_w
    ]

# 求解系统
initial = [1.0, 1.0, 1.0, 0.1]
sol = solve_ivp(chaos_system, (0, 50), initial, 
                t_eval=np.linspace(0, 50, 10000), method='RK45')

# 创建画布
plt.figure(figsize=(15, 20))

# 三维相空间图
ax1 = plt.subplot(321, projection='3d')
ax1.plot(sol.y[0], sol.y[1], sol.y[2], lw=0.3, alpha=0.7)
ax1.set_title("3D Phase Space (x-y-z)")
ax1.set_xlabel("X"), ax1.set_ylabel("Y"), ax1.set_zlabel("Z")

# 时间序列图
variables = ['x', 'y', 'z', 'w']
colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4']
for i in range(4):
    ax = plt.subplot(322 + i)
    ax.plot(sol.t, sol.y[i], color=colors[i], lw=0.5)
    ax.set_title(f"{variables[i]} Time Series")
    ax.set_xlabel("Time"), ax.set_ylabel("Value")
    ax.grid(alpha=0.3)

# 分布直方图
plt.subplot(325)
plt.hist(sol.y[0], bins=100, density=True, 
         color='#FF6B6B', edgecolor='black', alpha=0.7)
plt.title("x Value Distribution")

plt.subplot(326)
plt.hist(sol.y[3], bins=100, density=True, 
         color='#96CEB4', edgecolor='black', alpha=0.7)
plt.title("w Value Distribution")

plt.tight_layout()
plt.show()
