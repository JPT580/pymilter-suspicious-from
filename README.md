# pymilter-suspicious-from

This is a very rough python milter implementation which is supposed to parse `From:` header values and mark suspicious ones.

```
From: "Totally Official <totally.official@example.com>" <nope-its-fake@fake.example.net>
```

