# urld
URL handling for D

# Motivation
D's standard library has nothing for working with URLs.

Vibe.d can work with URLs. However, Vibe is big. Also, we want to work easily with query strings,
which vibe.d doesn't allow.

# Recent Breaking Changes

- v3.0:
	* urld does no automatic URL decoding
	* urld only automatically encodes non-ASCII characters
	* `URL(string)` constructor parses a URL rather than assigning the scheme only


# Installation
Add `"urld": "~>3.0.0"` to your `dub.json`.

# Usage

Parse a URL:

```D
auto url = "ircs://irc.freenode.com/#d".parseURL;
auto url = URL("ircs://irc.freenode.com/#d");
```

Construct one from scratch, laboriously:

```D
URL url;
with (url) {
	scheme = "soap.beep";
	host = "beep.example.net";
	port = 1772;
	path = "/serverinfo/info";
  queryParams.add("token", "my-api-token");
}
curl.get(url);
```

Unicode domain names:

```D
auto url = "http://☃.com/".parseURL;
writeln(url.toString);               // http://xn--n3h.com/
writeln(url.toHumanReadableString);  // http://☃.com/
```

Implicit conversion to strings for use with other libraries that expect URLs as strings:

```D
import std.net.curl;
auto couchdbURL = "http://couch.local:8815".parseURL;
writeln(get(couchdbURL ~ "users/bob.dobbs@subgenius.org"));
```

Autodetect ports:

```D
assert(parseURL("http://example.org").port == 80);
assert(parseURL("http://example.org:5326").port == 5326);
```

URLs of maximum complexity:

```D
auto url = parseURL("redis://admin:password@redisbox.local:2201/path?query=value#fragment");
assert(url.scheme == "redis");
assert(url.user == "admin");
assert(url.pass == "password");
// etc
```

URLs of minimum complexity:

```D
assert(parseURL("example.org").toString == "http://example.org/");
```

Canonicalization:

```D
assert(parseURL("http://example.org:80").toString == "http://example.org/");
```
