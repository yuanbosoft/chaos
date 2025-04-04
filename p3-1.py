import numpy as np
from scipy.integrate import solve_ivp
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D
import hashlib
import pyblake3  # 需安装：pip install pyblake3
from pysmx.SM3 import SM3  # 需安装：pip install pysmx

# 系统参数配置
σ, α = 10, 0.1
ρ, β = 28, 8/3
γ, δ, ε = 0.1, 10, 0.1
τ = 1.0
nonce = b'\x12\x34'  # 假设Nonce值

# 哈希到浮点数转换函数
def hash_to_float(data, bits=32):
    h = hashlib.shake_256(data).digest(bits//8)
    return int.from_bytes(h, 'big') / (1 << (bits))

# 各维度哈希函数封装
def blake3_perturbation(t):
    e_t = int(t * 1000).to_bytes(4, 'big')
    input_data = bytes([a ^ b for a, b in zip(e_t, nonce)])
    return pyblake3.blake3(input_data).digest()

def sm3_perturbation(w):
    w_bytes = np.float64(w).tobytes()
    sm3 = SM3()
    sm3.update(w_bytes)
    return sm3.digest()

def shake256_perturbation(t):
    t_mod = int(t % τ).to_bytes(4, 'big')
    return hashlib.shake_256(t_mod).digest(32)

def keccak_perturbation(x, y, z):
    xyz_bytes = b''.join([np.float64(v).tobytes() for v in [x,y,z]])
    return hashlib.sha3_256(xyz_bytes).digest()

# 四维混沌系统微分方程
def enhanced_chaos(t, state):
    x, y, z, w = state
    
    # 计算各哈希扰动项
    h_x = hash_to_float(blake3_perturbation(t)) * 2 - 1  # [-1,1]
    h_y = hash_to_float(sm3_perturbation(w)) * 2 - 1
    h_z = hash_to_float(shake256_perturbation(t)) * 2 - 1
    h_w = hash_to_float(keccak_perturbation(x,y,z)) * 2 - 1
    
    dxdt = σ*(y - x) + α * h_x
    dydt = x*(ρ - z) - y + β * h_y
    dzdt = x*y - β*z + γ * h_z
    dwdt = -δ*w + ε * h_w
    
    return [dxdt, dydt, dzdt, dwdt]

# 初始条件和时间范围
initial = [1.0, 1.0, 1.0, 0.1]
t_span = (0, 50)
t_eval = np.linspace(*t_span, 10000)

# 数值求解
sol = solve_ivp(enhanced_chaos, t_span, initial, t_eval=t_eval, method='RK45')

# 三维相空间绘图
fig = plt.figure(figsize=(12, 9))
ax = fig.add_subplot(111, projection='3d')
ax.plot(sol.y[0], sol.y[1], sol.y[2], lw=0.5)
ax.set_xlabel('X Axis')
ax.set_ylabel('Y Axis')
ax.set_zlabel('Z Axis')
ax.set_title('ST2DCKB-SEP 3D Phase Space Projection')
plt.show()
