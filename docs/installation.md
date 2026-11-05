# Установка на RED OS

Инструкция написана для хоста с RED OS и Podman 5.x. Веб-интерфейс работает в rootless-контейнере под обычным пользователем, захват трафика — в отдельном rootful-контейнере (см. [capture.md](capture.md)).

## Требования

- Podman 4.4 или новее: с этой версии есть Quadlet. Проверка: `podman --version`, `ls /usr/libexec/podman/quadlet`.
- Около 3 ГБ на образ и сколько угодно места под данные. PCAP и извлечённые файлы хранятся в каталоге данных.
- Доступ в интернет при сборке: Docker Hub, `deb.debian.org`, PyPI, `rules.emergingthreats.net`. В работе он нужен только для обновления IOC и правил.

## 1. Сборка образа

```bash
cd ~/trafficlens            # клон репозитория
podman build --format docker -t localhost/trafficlens:latest . 2>&1 | tee ~/trafficlens-build.log
```

- Базовый образ — `docker.io/zeek/zeek:lts` (Debian). Suricata, suricata-update и tcpdump ставятся из репозитория Debian, Python-зависимости — в venv.
- При сборке скачивается набор ET Open, поэтому образ сразу работает с правилами. Без сети при сборке используйте `--build-arg BAKE_RULES=0`, правила потом можно обновить из интерфейса.
- Другая версия Zeek: `--build-arg ZEEK_IMAGE=docker.io/zeek/zeek:8.0.11`.
- `--format docker` убирает безвредные предупреждения `SHELL is not supported for OCI image format`.

В конце сборка проверяет `zeek --version`, `suricata -V` и импорт приложения. Если появилось `Successfully tagged`, образ рабочий.

## 2. Проверка на тестовом PCAP

Прежде чем ставить сервис, убедитесь, что Zeek и Suricata в образе отрабатывают правильно:

```bash
mkdir -p ~/trafficlens/data/ioc/custom
cp tools/test-iocs.txt ~/trafficlens/data/ioc/custom/test.txt
alias tl='podman run --rm -v ~/trafficlens/data:/data:z -e TZ=Asia/Yekaterinburg localhost/trafficlens'
tl python3 /app/tools/make_test_pcap.py /data/test.pcap
tl update-iocs --source custom
tl analyze /data/test.pcap -o /data/test-report.html
```

Ожидаемый результат:

```
задача …: Обнаружены признаки компрометации; IOC: 4, алертов: N, файлов: 1
```

Тестовый PCAP содержит:
- DNS-резолв `api.evil-c2.example` в адрес 203.0.113.66;
- маячок с TLS на 203.0.113.66:8443 каждые 60 с;
- HTTP-загрузку файла EICAR с адреса `198.51.100.23/payload.exe`;
- DGA-подобный NXDOMAIN.

Все четыре IOC должны совпасть, файл `payload.exe` — появиться на вкладке «Файлы», маячок — в «Аномалиях». Число алертов Suricata зависит от версии набора правил.

После проверки удалите тестовые данные:

```bash
rm ~/trafficlens/data/ioc/custom/test.txt ~/trafficlens/data/test.pcap
```

## 3. Каталог данных, конфигурация и секреты

```bash
mkdir -p ~/trafficlens/data/config
cp deploy/trafficlens.yaml.example ~/trafficlens/data/config/trafficlens.yaml
cp deploy/trafficlens.env.example ~/.config/trafficlens.env
chmod 600 ~/.config/trafficlens.env
```

В `trafficlens.yaml` поправьте `local_nets`, то есть свои подсети. Всё остальное можно оставить по умолчанию; параметры описаны в самом файле.

В `~/.config/trafficlens.env` хранятся секреты. Чтобы строка заработала, уберите `#` в её начале и впишите значение после `=`. Кавычки не нужны: Podman читает значение буквально.

```
TZ=Asia/Yekaterinburg
TL_PASSWORD=пароль-для-веб-интерфейса
TL_ABUSECH_KEY=ключ-с-auth.abuse.ch
# TL_MISP_URL=https://misp.example
# TL_MISP_KEY=
# TL_OPENCTI_URL=https://opencti.example
# TL_OPENCTI_TOKEN=
```

| Переменная | Назначение |
|---|---|
| `TZ` | часовой пояс для времени в отчётах |
| `TL_PASSWORD` | пароль для входа в веб-интерфейс, логина нет. Пусто — без входа (подходит, если доступ закрыт логином в Caddy) |
| `TL_ABUSECH_KEY` | бесплатный Auth-Key abuse.ch, см. [iocs.md](iocs.md#abusech) |
| `TL_MISP_*`, `TL_OPENCTI_*` | подключение к своей TI-платформе, если она есть |

## 4. Запуск веб-интерфейса (Quadlet)

```bash
mkdir -p ~/.config/containers/systemd
cp deploy/quadlet/trafficlens.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start trafficlens
systemctl --user status trafficlens --no-pager
curl -s http://127.0.0.1:8095/healthz          # {"ok":true}
loginctl enable-linger $USER                   # чтобы сервис работал без активной сессии
```

Проверить, что Quadlet видит файл: `/usr/libexec/podman/quadlet -dryrun -user 2>&1 | grep -A3 -- '---trafficlens.service---'`.

Quadlet-юниты генерируются автоматически, `systemctl --user enable` для них не нужен: автозапуск задаёт секция `[Install]` в `.container`-файле.

## 5. Порт и доступ из сети

Внутри контейнера приложение слушает порт 8080. По умолчанию Quadlet публикует его на хосте как `127.0.0.1:8095`, то есть он доступен только с самого хоста или через обратный прокси на нём же.

### Вариант А: через Caddy

Добавьте сервис в каталог обратного прокси с апстримом на порт 8095 хоста. Если Caddy работает в rootless-контейнере, `127.0.0.1` хоста из него недоступен. Тогда используйте `host.containers.internal:8095` или опубликуйте порт на всех интерфейсах (вариант Б). Пример блока Caddyfile:

```caddy
trafficlens.apps.example {
    request_body { max_size 4GB }
    reverse_proxy host.containers.internal:8095 {
        transport http { read_timeout 30m write_timeout 30m }
    }
}
```

Увеличенный лимит тела запроса и таймауты нужны для загрузки больших PCAP.

### Вариант Б: напрямую из сети

1. Опубликуйте порт на всех интерфейсах:
   ```bash
   sed -i 's|^PublishPort=.*|PublishPort=8095:8080|' ~/.config/containers/systemd/trafficlens.container
   systemctl --user daemon-reload && systemctl --user restart trafficlens
   ss -tlnp | grep 8095          # *:8095 … "pasta"
   ```
2. Откройте порт в firewalld. Лучше открывать только для своих адресов:
   ```bash
   sudo firewall-cmd --get-active-zones        # в какой зоне сетевая карта
   sudo firewall-cmd --permanent --zone=public \
     --add-rich-rule='rule family="ipv4" source address="192.168.1.0/24" port port="8095" protocol="tcp" accept'
   sudo firewall-cmd --reload
   ```
3. Обязательно задайте `TL_PASSWORD`.

**Клиенты через VPN или из других сетей.** Если firewalld отвечает `Connection refused`, значит, адрес клиента не попал в правило. Узнать, с какого адреса приходит запрос:

```bash
sudo tcpdump -ni <интерфейс> -c 3 'tcp port 8095 and tcp[tcpflags] & tcp-syn != 0'
```

Затем добавьте ещё одно правило для этого адреса, например `source address="172.16.6.2/32"`.

## 6. SELinux

Отдельная настройка не нужна:

- Порт публикует rootless Podman (`pasta`), а не системная служба, поэтому `semanage port` не требуется.
- Каталог данных монтируется с меткой `:z`, Podman сам перемаркирует его в `container_file_t`. Метка именно `:z` (общая), а не `:Z`, потому что подкаталог `spool/` монтирует ещё и контейнер захвата.

Если что-то упирается в SELinux, посмотрите отказы:

```bash
sudo ausearch -m avc -ts recent | grep -i -E 'trafficlens|container'
```

## 7. Обновление

```bash
cd ~/trafficlens && git pull
podman build --format docker -t localhost/trafficlens:latest .
systemctl --user restart trafficlens
bash tools/smoke_server.sh
# если используется захват:
podman save localhost/trafficlens:latest | sudo podman load
sudo systemctl restart trafficlens-capture
```

Данные, база IOC и скачанные правила лежат в каталоге данных и при обновлении образа сохраняются.

## Командная строка

```bash
podman exec trafficlens python3 -m trafficlens update-iocs                 # все источники
podman exec trafficlens python3 -m trafficlens update-iocs --source custom # один источник
podman exec trafficlens python3 -m trafficlens update-rules                # ET Open
podman exec trafficlens python3 -m trafficlens analyze /data/file.pcap     # анализ файла из каталога данных
```

Источники: `custom`, `abusech-urlhaus`, `abusech-threatfox`, `abusech-feodo`, `abusech-malwarebazaar`, `misp`, `opencti`.
