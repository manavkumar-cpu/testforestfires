import matplotlib.pyplot as plt

# Noise errors from DP
errors = [-3, 2, 1, -4, 2, -1, 3, -2, 1, -3]  # Sample noise values

plt.figure(figsize=(10, 6))
plt.hist(errors, bins=10, color='lightblue', edgecolor='black', alpha=0.7)

plt.xlabel('Noise Added (Packets)')
plt.ylabel('Frequency')
plt.title('Distribution of DP Noise in Flow Data')
plt.axvline(x=0, color='red', linestyle='--', linewidth=2, label='Zero Error')
plt.legend()
plt.grid(True, alpha=0.3)
plt.show()