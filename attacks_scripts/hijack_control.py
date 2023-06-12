import socket
import keyboard
import cv2
import threading


def send_command(command_socket, command_addr, command):
    command_socket.sendto(command.encode('utf-8'), command_addr)
    response, ip = command_socket.recvfrom(1024)
    print(response.decode('utf-8'))


def takeoff(command_socket, command_addr):
    send_command(command_socket, command_addr, "takeoff")


def land(command_socket, command_addr):
    send_command(command_socket, command_addr, "land")


def watch_video_stream(command_socket, command_addr):
    command_socket.sendto(b"streamon", command_addr)
    print("\n   video streaming started!")
    cap = cv2.VideoCapture('udp://192.168.10.1:11111')
    while True:
        ret, frame = cap.read()
        if ret:
            cv2.imshow('Tello Video Stream', frame)
            key = cv2.waitKey(1) & 0xFF
            if key == 27:  # 'Esc' key
                break
        else:
            break
    cap.release()
    cv2.destroyAllWindows()


def main():
    print("   Connect to Tello wifi and press <<Shift>>")
    while not keyboard.is_pressed("Shift"):
        pass
    print("   Starting")
    command_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    command_addr = ('192.168.10.1', 8889)
    command_socket.bind(('', 8889))
    command_socket.sendto(b"command", command_addr)
    command_socket.recvfrom(1024)
    print("Control has taken successfully!")
    video_thread = threading.Thread(target=watch_video_stream, args=(command_socket, command_addr))
    video_thread.daemon = True
    video_thread.start()

    print("""
   press t to takeoff
   press l to land
   press 5 to exit
   press 1 to capture stream
        """)
    while not keyboard.is_pressed("5"):
        if keyboard.is_pressed("t"):
            takeoff(command_socket, command_addr)
        elif keyboard.is_pressed("l"):
            land(command_socket, command_addr)
        elif keyboard.is_pressed("1"):
            video_thread = threading.Thread(target=watch_video_stream, args=(command_socket, command_addr))
            video_thread.daemon = True
            video_thread.start()

    command_socket.close()


if __name__ == "__main__":
    main()
