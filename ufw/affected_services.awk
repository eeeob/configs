# يستقبل مخرجات: ss -tulnpH
# ويطبع الخدمات المستمعة على بورتات عامة (غير loopback وغير SSH) التي ستتأثر بتفعيل UFW
# الاستخدام: ss -tulnpH | awk -v ssh=<ssh_port> -f affected_services.awk
{
    n = split($5, a, ":");
    port = a[n];
    proc = "unknown";
    if (match($0, /users:\(\("[^"]+"/)) {
        proc = substr($0, RSTART + 9, RLENGTH - 9);
    }
    # تجاهل الخدمات المستمعة على loopback فقط لأنها لا تتأثر بالجدار الناري
    if ($5 ~ /^127\./ || $5 ~ /^\[::1\]/) next;
    if (port == ssh) next;
    key = $1 " " port " " proc;
    if (!(key in seen)) {
        seen[key] = 1;
        printf "  - %s port %s (%s)\n", $1, port, proc;
    }
}
