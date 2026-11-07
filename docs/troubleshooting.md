# Решение проблем

Почти всё, что нужно для диагностики, лежит в каталоге задачи `~/trafficlens/data/jobs/<id>/`:

```bash
J=~/trafficlens/data/jobs/<id>
cat $J/job.log                                         # команды Zeek/Suricata и их вывод
ls -la $J/zeek                                         # какие логи создал Zeek
grep -o '"event_type":"[a-z]*"' $J/suricata/eve.json | sort | uniq -c
```

Журнал сервиса: `journalctl --user -u trafficlens -n 50 --no-pager`, для захвата — `sudo journalctl -u trafficlens-capture -n 50 --no-pager`.

## Установка

### `Unit trafficlens.service not found`

Quadlet не нашёл файл `trafficlens.container`. Проверьте:

```bash
ls -la ~/.config/containers/systemd/trafficlens.container
/usr/libexec/podman/quadlet -dryrun -user 2>&1 | grep -A3 -- '---trafficlens.service---'
```

Частая причина — файл открыли в редакторе, не скопировав его перед этим из `deploy/quadlet/`, и вышли без сохранения. Скопируйте файл и выполните `systemctl --user daemon-reload`. Для захвата файл должен лежать в `/etc/containers/systemd/`, а `daemon-reload` выполняется через `sudo`.

### Сервис не стартует сразу после установки

Если указанного в Quadlet-файле `EnvironmentFile` (`~/.config/trafficlens.env`) нет, контейнер не запустится. Создайте файл из `deploy/trafficlens.env.example`.

### `status=143` и `Failed with result 'exit-code'` при перезапуске

Это не сбой. `podman stop` завершает контейнер сигналом SIGTERM, и код выхода получается 128 + 15 = 143, а systemd по умолчанию считает успешным только 0. В Quadlet-файлах из `deploy/quadlet/` уже есть `SuccessExitStatus=143`. Если ваш файл скопирован раньше, добавьте эту строку в секцию `[Service]` и выполните `systemctl --user daemon-reload` (для захвата — `sudo systemctl daemon-reload`).

### Как убедиться, что после обновления работает новый образ

```bash
podman exec trafficlens python3 -c "import trafficlens, trafficlens.quality; print(trafficlens.__version__)"
```

`ModuleNotFoundError` значит, что контейнер запущен со старым образом: выполните `git pull`, пересоберите образ и перезапустите сервис.

### Предупреждения `SHELL is not supported for OCI image format` при сборке

Они безвредны: так Podman сообщает об инструкции `SHELL` в базовом образе Zeek. Убираются флагом `podman build --format docker`.

## Доступ к веб-интерфейсу

### С хоста работает, из сети — нет

```bash
ss -tlnp | grep 8095          # должно быть *:8095, а не 127.0.0.1:8095
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --list-rich-rules | grep 8095
```

- Видно `127.0.0.1:8095` → в Quadlet-файле `PublishPort=127.0.0.1:8095:8080`. Замените на `8095:8080`, выполните `daemon-reload` и `restart`.
- Правило firewalld есть, но клиент получает `Connection refused` → адрес клиента не попадает в правило. Типичный случай — VPN: запрос приходит не из домашней подсети, а с адреса туннеля. Посмотрите адрес с помощью `sudo tcpdump -ni <интерфейс> -c 3 'tcp port 8095 and tcp[tcpflags] & tcp-syn != 0'` и добавьте отдельное правило для него.
- Правило добавлено не в ту зону → укажите `--zone=` той зоны, в которой находится сетевая карта.

### Большой PCAP не загружается

- Ошибка «Файл больше разрешённого размера» → увеличьте `max_upload_mb` в `trafficlens.yaml`.
- Загрузка через Caddy обрывается → увеличьте `request_body max_size` и таймауты `reverse_proxy` (см. [installation.md](installation.md#вариант-а-через-caddy)).

## Анализ

### В отчёте нет HTTP и файлов, а в `conn.log` каждый пакет записан отдельным соединением

Признаки:
- у одного 5-tuple много записей с разными `uid`;
- `history` у каждой записи из одного символа: `S`, `^h`, `A`, `D`;
- `http.log` и `files.log` не созданы.

Это значит, что пакеты в PCAP идут не по возрастанию времени. Zeek ведёт соединения по меткам времени пакетов, и сессия «из прошлого» распадается на отдельные пакеты. В обычном захвате tcpdump так не бывает. Такое случается с PCAP, склеенными из нескольких файлов или сгенерированными вручную. Отсортируйте пакеты по времени: `reordercap in.pcap out.pcap` из пакета wireshark-cli, или склеивайте файлы через `mergecap`, который сохраняет порядок.

### «Компрометация» на обычном трафике из-за TLS-сертификатов

В старых версиях каждая строка «TLS с невалидным сертификатом» давала +10, и записи прошлых лет набирали сотни очков. Статус `unable to get local issuer certificate` обычно значит, что в хранилище корней Zeek нет нужного корня или промежуточного сертификата: в Mozilla-хранилище свежего образа нет многих корней 2018–2020 годов, и Zeek их не догружает. С версии 0.2 такие статусы помечаются «слабый признак» и не дают очков. Для старых задач нажмите «Пересверить IOC». Подробнее — [report.md](report.md#итог-скоринговый-вердикт).

### Тысячи алертов `SURICATA TCPv4 invalid checksum`

PCAP записан на машине с checksum offload: контрольные суммы считает сетевая карта, и в захвате они «битые». Флаг `-k none` такие алерты не убирает: правила `decoder-events` проверяют суммы явно. С версии 0.2 они скрываются в отчёте (`suricata.suppress_signatures`) и отключаются в Suricata при следующем «Обновить правила» (`suricata.disable_rules`). При захвате на своём хосте можно ещё отключить offload: `ethtool -K <интерфейс> rx off tx off`.

### `Zeek не найден` или `Suricata не найдена` на главной странице

Приложение запущено не в образе TrafficLens (например, локально для разработки). В образе оба движка проверяются на этапе сборки.

### Правил Suricata нет

Набор ET Open не скачался при сборке (`BAKE_RULES=0` или не было сети). Нажмите «Обновить ET Open» на странице «Индикаторы и правила» или выполните `podman exec trafficlens python3 -m trafficlens update-rules`.

### Анализ маленького PCAP занимает почти минуту

Это нормально. Почти всё время Suricata загружает и компилирует 50+ тысяч правил ET Open, а на больших файлах это время почти не растёт.

### Источник IOC с ошибкой `HTTP 401` / `HTTP 403`

Для abuse.ch: Auth-Key не задан или неверен (см. [iocs.md](iocs.md#abusech)). Для MISP и OpenCTI: проверьте ключ или токен и права пользователя на чтение атрибутов или индикаторов.

### `нет соединения с источником`

С хоста нет доступа к источнику: прокси, DNS или firewall на исходящие соединения. Проверьте из контейнера:

```bash
podman exec trafficlens python3 -c "import requests; print(requests.get('https://feodotracker.abuse.ch/downloads/ipblocklist.json', timeout=20).status_code)"
```

### Ошибки SSL при подключении к MISP/OpenCTI

Сертификат выдан внутренним CA. Положите CA в `<каталог данных>/config/` и укажите путь в `verify_tls`.

## Живой захват

### Блок «Живой захват» серый

- Контейнер захвата не запущен → `sudo systemctl status trafficlens-capture`.
- В Quadlet-файле захвата не заменён `/home/USER/` → смонтирован не тот каталог.
- Неверное имя интерфейса → `ip -br link`, параметр `CAPTURE_IFACE`.

### Файлы захвата не забираются на анализ

Веб-контейнер должен уметь переносить файлы из `spool/ready/`, то есть каталог должен принадлежать пользователю:

```bash
ls -ld ~/trafficlens/data/spool ~/trafficlens/data/spool/ready
sudo chown $USER: ~/trafficlens/data/spool ~/trafficlens/data/spool/ready
```

### Файлы захвата слишком большие

Исключите внутренний трафик: укажите конкретный интерфейс вместо `any` и отфильтруйте порты Graylog, OpenSearch и других сервисов в `CAPTURE_FILTER` (см. [capture.md](capture.md#фильтр-исключите-поток-логов)).
