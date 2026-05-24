def generate_frpc_config(subdomain, ports, server_addr, server_port, token):
    lines = [
        f'serverAddr = "{server_addr}"',
        f'serverPort = {server_port}',
        '',
        '[auth]',
        'method = "token"',
        f'token = "{token}"',
        '',
    ]
    labels = ["mikrotik-api", "winbox", "ssh", "http", "custom"]
    for i, port in enumerate(ports):
        label = labels[i] if i < len(labels) else f"port{i+1}"
        lines += [
            '[[proxies]]',
            f'name = "{subdomain}-{label}"',
            'type = "tcp"',
            'localIP = "192.168.1.1"',
            'localPort = 8728',
            f'remotePort = {port}',
            '',
        ]
    return "\n".join(lines)
