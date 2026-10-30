# acme/hello — пример расширения Bastion

```bash
bin/bastion-ext keygen ~/acme.key          # один раз: печатает publisher_key для extension.json
bin/bastion-ext pack examples/extensions/acme-hello ~/acme.key acme-hello.zip
```

Загрузите `acme-hello.zip` и `acme-hello.zip.sig` в «Admin → Extensions», сверьте отпечаток ключа и включите.
Ключ в `extension.json` этого примера сгенерирован для демонстрации — замените его своим.
