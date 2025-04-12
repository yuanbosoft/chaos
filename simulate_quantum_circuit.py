import time
from qiskit import QuantumCircuit, Aer, transpile
from qiskit.tools.monitor import job_monitor

def simulate_quantum_circuit(n_qubits=28, use_mps=False, max_parallel=32):
    """
    模拟量子电路并返回结果（支持全态和MPS近似）
    
    参数：
    - n_qubits: 量子比特数（建议全态≤30，MPS≤40）
    - use_mps: 是否启用矩阵乘积态（MPS）近似
    - max_parallel: 并行线程数（设为CPU核心数）
    """
    # 创建简单测试电路（Grover算法模板）
    qc = QuantumCircuit(n_qubits)
    qc.h(range(n_qubits))          # 叠加态
    qc.cz(0, n_qubits-1)           # 纠缠操作
    qc.h(range(n_qubits))          # Grover扩散算子
    qc.measure_all()

    # 配置模拟器参数
    if use_mps:
        # MPS近似模式（需要Qiskit ≥0.16.0，v0.45.1可能不支持）
        backend = Aer.get_backend('matrix_product_state')
        config = {
            "max_parallel_threads": max_parallel,
            "mps_sample_measure_algorithm": 'mps_apply_measure'  # 测量优化
        }
    else:
        # 全态向量模式（内存敏感！）
        backend = Aer.get_backend('statevector_simulator')
        config = {
            "max_parallel_threads": max_parallel,
            "blocking_enable": True,          # 启用内存分块
            "blocking_qubits": 28              # 每块处理28量子比特（内存控制）
        }

    # 运行模拟
    try:
        start_time = time.time()
        job = backend.run(transpile(qc, backend), **config)
        job_monitor(job)
        result = job.result()
        elapsed = time.time() - start_time

        # 获取结果
        if use_mps:
            counts = result.get_counts()
            print(f"MPS模拟完成！耗时：{elapsed:.2f}s，测量计数：{counts}")
        else:
            statevector = result.get_statevector()
            print(f"全态模拟完成！耗时：{elapsed:.2f}s，内存占用：{statevector.size * 16 / 1e9:.2f}GB")

    except MemoryError:
        print(f"内存不足！{n_qubits}量子比特需要约{2**n_qubits * 16 / 1e9:.2f}GB内存")
    except Exception as e:
        print(f"模拟失败：{str(e)}")

if __name__ == "__main__":
    # 示例1：全态模拟30量子比特（需要约16GB内存）
    print("==== 全态模拟30量子比特 ====")
    simulate_quantum_circuit(n_qubits=30, use_mps=False)

    # 示例2：尝试MPS模拟35量子比特（需Qiskit升级到新版）
    # print("\n==== MPS模拟35量子比特 ====")
    # simulate_quantum_circuit(n_qubits=35, use_mps=True)
