import socket
import threading

def string_to_matrix(s):
    rows = s.strip().split(";")
    matrix = []
    for row in rows:
        matrix.append([int(x) for x in row.split(",")])
    return matrix

def matrix_to_string(matrix):
    return ";".join(",".join(str(x) for x in row) for row in matrix)

def multiply_matrices(A, B):
    result = [[0 for _ in range(len(B[0]))] for _ in range(len(A))]
    for i in range(len(A)):
        for j in range(len(B[0])):
            for k in range(len(B)):
                result[i][j] += A[i][k] * B[k][j]
    return result

def handle_client(client_socket, client_address):
    print(f"[CONNECTED] {client_address}")

    try:
        data = client_socket.recv(4096).decode()
        A_str, B_str = data.split("|")

        A = string_to_matrix(A_str)
        B = string_to_matrix(B_str)

        result = multiply_matrices(A, B)

        result_str = matrix_to_string(result)
        client_socket.send(result_str.encode())

    except Exception as e:
        print("Error:", e)

    client_socket.close()
    print(f"[DISCONNECTED] {client_address}")

server = socket.socket()
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(("localhost", 5555))
server.listen(5)

print("Socket Server running...")

while True:
    client_socket, client_address = server.accept()

    thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address)
    )
    thread.start()
