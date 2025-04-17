namespace CheckHeaders.Services;

public static class CSPInspector
{
    public static bool IsCSPUnsafeDetailed(string cspHeader, out Dictionary<string, string> issues)
    {
        issues = new Dictionary<string, string>();

        if (string.IsNullOrWhiteSpace(cspHeader))
        {
            issues["missing-csp"] = "Missing CSP header — no protection against script injection attacks.";
            return true;
        }

        string csp = cspHeader.ToLowerInvariant();

        Dictionary<string, List<string>> directives = ParseCSPDirectives(csp);

        foreach (var directive in directives)
        {
            string name = directive.Key;
            List<string> values = directive.Value;

            switch (name)
            {
                case "script-src":
                    if (values.Contains("'unsafe-inline'"))
                        issues["script-src 'unsafe-inline'"] = "Allows inline JavaScript — vulnerable to XSS.";
                    if (values.Contains("'unsafe-eval'"))
                        issues["script-src 'unsafe-eval'"] = "Allows `eval()` and similar — vulnerable to code injection.";
                    if (values.Contains("*"))
                        issues["script-src *"] = "Allows scripts from any origin — very risky.";
                    break;

                case "style-src":
                    if (values.Contains("'unsafe-inline'"))
                        issues["style-src 'unsafe-inline'"] = "Allows inline styles — can be used for injection.";
                    if (values.Contains("*"))
                        issues["style-src *"] = "Allows styles from any origin — not recommended.";
                    break;

                case "default-src":
                    if (values.Contains("*"))
                        issues["default-src *"] = "Default allows all content sources — defeats CSP purpose.";
                    break;

                case "object-src":
                    if (values.Contains("*"))
                        issues["object-src *"] = "Allows embedding plugins — Flash/Java objects can be dangerous.";
                    if (!directives.ContainsKey("object-src"))
                        issues["object-src missing"] = "Missing object-src directive — might fall back to default-src which may be unsafe.";
                    break;

                case "frame-ancestors":
                    if (values.Contains("*"))
                        issues["frame-ancestors *"] = "Allows embedding your site in any frame — clickjacking risk.";
                    break;
            }

            foreach (string val in values)
            {
                if (val.StartsWith("data:"))
                    issues[$"{name} data:"] = "Allows data: URIs — may allow injection of inline resources.";
                if (val.StartsWith("blob:"))
                    issues[$"{name} blob:"] = "Allows blob: URIs — can be used for bypassing CSP.";
                if (val.StartsWith("filesystem:"))
                    issues[$"{name} filesystem:"] = "Allows filesystem: URIs — rarely used and often dangerous.";
            }
        }

        return issues.Count > 0;
    }

    private static Dictionary<string, List<string>> ParseCSPDirectives(string csp)
    {
        var result = new Dictionary<string, List<string>>();
        var parts = csp.Split(';', StringSplitOptions.RemoveEmptyEntries);

        foreach (string part in parts)
        {
            string[] tokens = part.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (tokens.Length == 0) continue;

            string directive = tokens[0];
            List<string> values = new List<string>(tokens.Length - 1);
            for (int i = 1; i < tokens.Length; i++)
            {
                values.Add(tokens[i]);
            }

            result[directive] = values;
        }

        return result;
    }
}
