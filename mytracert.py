import socket
import struct
import select
import time
import sys
import os
import argparse
import functools

# Каждый print сразу появлялся в терминале, без буферизации
print = functools.partial(print, flush=True)

# Константы ICMP
ICMP_ECHO_REQUEST  = 8   # тип: Echo Request
ICMP_ECHO_REPLY    = 0   # тип: Echo Reply
ICMP_TIME_EXCEEDED = 11  # тип: TTL истёк
ICMP_DEST_UNREACH  = 3   # тип: Destination Unreachable

# Кол-во пакетов слать на каждый TTL
PACKETS_PER_HOP = 3

# Таймаут ожидания ответа в секундах
TIMEOUT = 3

# Максимальное число хопов
MAX_HOPS = 30

def checksum(data: bytes) -> int:
    if len(data) % 2 != 0:
        data += b'\x00'  # дополняем до чётного числа байт

    total = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        total += word

    # Добавляем переполнение обратно в младшие 16 бит
    total = (total >> 16) + (total & 0xFFFF)
    total += (total >> 16) # Нужен на случай если после предыдущего шага снова возникло переполнение

    return ~total & 0xFFFF  # инвертируем и берём 16 бит

def build_icmp_packet(seq: int, pid: int) -> bytes:
    icmp_type = ICMP_ECHO_REQUEST
    icmp_code = 0
    chk = 0          # временно 0, потом заменим настоящей суммой
    identifier = pid & 0xFFFF
    sequence = seq

    # Забиваем данные нулями
    payload = b'\x00' * 64

    # Собираем заголовок с нулевой контрольной суммой
    header = struct.pack('!BBHHH', icmp_type, icmp_code, chk, identifier, sequence) #8 байт

    # Считаем настоящую контрольную сумму по заголовку и данным
    chk = checksum(header + payload)

    # Пересобираем заголовок с правильной суммой
    header = struct.pack('!BBHHH', icmp_type, icmp_code, chk, identifier, sequence)

    return header + payload


def send_one_ping(sock: socket.socket, dest_addr: str, seq: int, ttl: int, pid: int) -> float:
    # Устанавливаем TTL через опцию сокета IP_TTL
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)

    packet = build_icmp_packet(seq, pid)
    send_time = time.time()
    # Порт назначения для raw ICMP сокета игнорируется, ставим 1
    sock.sendto(packet, (dest_addr, 1))
    return send_time

def receive_one_ping(sock: socket.socket, pid: int, timeout: float):
    deadline = time.time() + timeout

    while True:
        remaining = deadline - time.time()
        if remaining <= 0:
            return None  # таймаут

        # select позволяет ждать данные без блокировки навсегда
        ready = select.select([sock], [], [], remaining)
        if not ready[0]:
            return None  # таймаут

        recv_time = time.time()
        raw_packet, addr = sock.recvfrom(1024)

        # IP-заголовок занимает минимум 20 байт, после него идёт ICMP
        ip_header_len = (raw_packet[0] & 0x0F) * 4
        icmp_data = raw_packet[ip_header_len:]

        if len(icmp_data) < 8:
            continue  # слишком короткий пакет, пропускаем

        icmp_type, icmp_code = icmp_data[0], icmp_data[1]

        if icmp_type == ICMP_ECHO_REPLY:
            # Проверяем, что это ответ именно на наш запрос (по identifier)
            recv_id = struct.unpack('!H', icmp_data[4:6])[0]
            if recv_id == (pid & 0xFFFF):
                return recv_time, addr[0], icmp_type

        elif icmp_type == ICMP_TIME_EXCEEDED:
            if len(icmp_data) >= 8:
                inner_ip_start = 8
                inner_ip_len = (icmp_data[inner_ip_start] & 0x0F) * 4
                inner_icmp_start = inner_ip_start + inner_ip_len

                if len(icmp_data) >= inner_icmp_start + 8:
                    orig_id = struct.unpack('!H', icmp_data[inner_icmp_start + 4:inner_icmp_start + 6])[0]
                    if orig_id == (pid & 0xFFFF):
                        return recv_time, addr[0], icmp_type

        elif icmp_type == ICMP_DEST_UNREACH:
            if len(icmp_data) >= 8:
                inner_ip_start = 8
                inner_ip_len = (icmp_data[inner_ip_start] & 0x0F) * 4
                inner_icmp_start = inner_ip_start + inner_ip_len
                if len(icmp_data) >= inner_icmp_start + 8:
                    orig_id = struct.unpack('!H', icmp_data[inner_icmp_start + 4:inner_icmp_start + 6])[0]
                    if orig_id == (pid & 0xFFFF):
                        return recv_time, addr[0], icmp_type

def resolve_hostname(ip: str) -> str:
    try:
        name = socket.gethostbyaddr(ip)[0]
        return name
    except (socket.herror, socket.gaierror):
        return ip  # если не разрешилось - возвращаем IP как есть

def mytracert(dest: str, resolve_dns: bool = False):
    # если передан IP - просто вернёт его же)
    try:
        dest_ip = socket.gethostbyname(dest)
    except socket.gaierror as e:
        print(f"mytracert: не удалось разрешить адрес '{dest}': {e}")
        sys.exit(1)

    print(f"\nmytracert до {dest} [{dest_ip}], макс. {MAX_HOPS} хопов:\n")

    # PID процесса используем как identifier в ICMP, чтобы не перепутать наши пакеты с чужими
    pid = os.getpid()

    # Создаём raw socket для ICMP
    # SOCK_RAW + IPPROTO_ICMP - получаем полный IP-пакет в ответах
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except PermissionError:
        print("Ошибка: нужны права администратора для raw sockets!")
        print("Запустите командную строку от имени администратора.")
        sys.exit(1)

    sock.settimeout(TIMEOUT)

    seq = 0  # глобальный sequence number, увеличиваем для каждого пакета

    try:
        for ttl in range(1, MAX_HOPS + 1):
            hop_addr = None   # адрес узла на этом хопе
            reached  = False  # True когда дошли до цели

            # Сразу печатаем номер хопа - время допечатаем по мере прихода,
            # адрес - в конце. end="" чтобы не переводить строку раньше времени
            print(f"  {ttl:2d}  ", end="")

            for _ in range(PACKETS_PER_HOP):
                seq += 1  # каждый пакет получает уникальный sequence number

                send_time = send_one_ping(sock, dest_ip, seq, ttl, pid)
                result = receive_one_ping(sock, pid, TIMEOUT)

                if result is None:
                    print("   *   ", end="")
                else:
                    recv_time, addr, icmp_type = result
                    rtt_ms = (recv_time - send_time) * 1000  # переводим в мс
                    print(f"{rtt_ms:5.1f} ms  ", end="")
                    hop_addr = addr

                    if addr == dest_ip:
                        reached = True

            # После трёх замеров печатаем адрес узла и переводим строку
            if hop_addr is None:
                print("* Нет ответа")
            else:
                if resolve_dns:
                    hostname = resolve_hostname(hop_addr)
                    print(f"{hostname} [{hop_addr}]")
                else:
                    print(hop_addr)

            # Если получили Echo Reply от цели - маршрут построен, выходим
            if reached:
                break

    finally:
        sock.close()

    print("\nТрассировка завершена.")

# Точка входа
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='mytracert - простой аналог tracert для Windows (ICMP)',
        epilog='Пример: python mytracert.py google.com -r'
    )
    parser.add_argument(
        'destination',
        help='IP-адрес или доменное имя целевого узла'
    )
    parser.add_argument(
        '-r', '--resolve',
        action='store_true',
        help='включить обратный DNS (показывать имена хостов)'
    )

    args = parser.parse_args()

    mytracert(args.destination, resolve_dns=args.resolve)