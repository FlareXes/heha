import dns.resolver

def get_dns_records(domain):
    try:
        result = dns.resolver.resolve(domain, 'A')  # Change 'A' to the record type you're interested in (e.g., 'MX', 'CNAME', etc.)
        for data in result:
            print(f"{domain} {result.qtype} {data}")
    except dns.resolver.NXDOMAIN:
        print(f"Domain '{domain}' not found.")
    except dns.resolver.NoAnswer:
        print(f"No {result.qtype} records found for '{domain}'.")
    except dns.resolver.Timeout:
        print("DNS resolution timed out.")

# Replace 'example.com' with the domain you want to query
get_dns_records('example.com')
