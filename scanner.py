def scanner(ip, ports, send_technique, interpretation_technique, timeout):
    results = []

    for port in ports:
        response = send_technique(ip, port, timeout)
        state = interpretation_technique(response)

        results.append({
            "port": port,
            "state": state
        })

    return results