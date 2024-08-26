import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# Parameters for the Lorenz system
sigma = 10
rho = 28
beta = 8/3

# Time step and number of iterations
dt = 0.01
num_steps = 10000

# Initialize arrays
x = np.zeros(num_steps)
y = np.zeros(num_steps)
z = np.zeros(num_steps)

# Initial conditions
x[0], y[0], z[0] = 0.0, 1.0, 1.05

# Iteratively calculate the values
for i in range(1, num_steps):
    x[i] = x[i-1] + sigma * (y[i-1] - x[i-1]) * dt
    y[i] = y[i-1] + (x[i-1] * (rho - z[i-1]) - y[i-1]) * dt
    z[i] = z[i-1] + (x[i-1] * y[i-1] - beta * z[i-1]) * dt

# Plot the Lorenz attractor with black lines
fig = plt.figure()
ax = fig.add_subplot(111, projection='3d')
ax.plot(x, y, z, lw=0.5, color='black')
ax.set_xlabel('X axis')
ax.set_ylabel('Y axis')
ax.set_zlabel('Z axis')
ax.set_title("Lorenz Attractor")

plt.show()
