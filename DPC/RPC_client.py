import xmlrpc.client

proxy = xmlrpc.client.ServerProxy("http://localhost:6000/")

A = [
    [2, 0, 1],
    [3, 4, 2],
    [1, 2, 3]
]

B = [
    [1, 2, 3],
    [0, 1, 4],
    [5, 6, 0]
]

result = proxy.multiply(A, B)

print("Result Matrix (RPC):")
for row in result:
    print(row)
