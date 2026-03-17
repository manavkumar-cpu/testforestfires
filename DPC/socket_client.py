import socket

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

def matrix_to_string(matrix):
    return ";".join(",".join(str(x) for x in row) for row in matrix)

def string_to_matrix(s):
    rows = s.strip().split(";")
    matrix = []
    for row in rows:
        matrix.append([int(x) for x in row.split(",")])
    return matrix

client = socket.socket()
client.connect(("localhost", 5555))

data = matrix_to_string(A) + "|" + matrix_to_string(B)
client.send(data.encode())

result_data = client.recv(4096).decode()
result = string_to_matrix(result_data)

print("Result Matrix :")
for row in result:
    print(row)

client.close()
