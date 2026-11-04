# Живой захват

Контейнер `trafficlens-capture` запускает tcpdump с ротацией файлов. Закрытый файл переносится в `spool/ready/`, веб-контейнер забирает его оттуда и ставит в очередь анализа. Анализ идёт в веб-контейнере, а контейнер захвата только пишет пакеты.

```
enp4s0f0 ─► tcpdump -G 300 ─► spool/cap-20261104-120000.pcap
                                  │ файл закрыт (tcpdump -z)
                                  ▼
                              spool/ready/ ─► веб-контейнер ─► задача «захват»
```

## Почему rootful

Захват с интерфейса хоста требует `--network=host` и `CAP_NET_RAW`, а rootless Podman этого дать не может. Поэтому контейнер захвата запускается от root. Ему монтируется только `spool/`, к остальным данным доступа у него нет.

## Установка

```bash
# образ в хранилище root
podman save localhost/trafficlens:latest | sudo podman load

# имя сетевого интерфейса
ip -br link

sudo cp deploy/quadlet/trafficlens-capture.container /etc/containers/systemd/
sudo sed -i \
  -e "s|/home/USER/|$HOME/|" \
  -e 's|^Environment=CAPTURE_IFACE=.*|Environment=CAPTURE_IFACE=enp4s0f0|' \
  /etc/containers/systemd/trafficlens-capture.container

mkdir -p ~/trafficlens/data/spool/ready
sudo systemctl daemon-reload
sudo systemctl start trafficlens-capture
sudo systemctl status trafficlens-capture --no-pager
```

Захват работает, если:
- на главной странице в блоке «Живой захват» горит зелёная точка и указан текущий файл;
- через время ротации (по умолчанию 5 минут) в списке анализов появляется задача с источником «захват».

## Параметры

Задаются строками `Environment=` в `/etc/containers/systemd/trafficlens-capture.container`. После изменения выполните `sudo systemctl daemon-reload && sudo systemctl restart trafficlens-capture`.

| Переменная | По умолчанию | Назначение |
|---|---|---|
| `CAPTURE_IFACE` | `any` | интерфейс захвата. Укажите реальный, см. ниже |
| `CAPTURE_ROTATE` | `300` | длина одного файла в секундах. Каждый файл становится отдельным анализом |
| `CAPTURE_FILTER` | см. файл | BPF-фильтр |
| `CAPTURE_SNAPLEN` | `0` | сколько байт пакета сохранять (0 — целиком; иначе не будет извлечения файлов) |
| `CAPTURE_MAX_SPOOL_MB` | `5120` | предел для файлов в `ready/`, которые ещё не забраны на анализ. При превышении удаляются самые старые |

### Интерфейс: лучше не `any`

`any` захватывает и `lo`. На хосте с Graylog, OpenSearch и MongoDB через localhost идёт большой внутренний трафик: Graylog ↔ OpenSearch (9200/9300) и Graylog ↔ MongoDB (27017). С `any` он целиком попадёт в PCAP. Укажите физический интерфейс или зеркальный порт.

### Фильтр: исключите поток логов

Если на хосте работает Graylog, логи с других машин приходят на его инпуты по сети и попадают в захват. Исключите эти порты и собственный порт TrafficLens:

```bash
ss -tulnp | grep -i java      # порты инпутов Graylog
```

```
Environment="CAPTURE_FILTER=not port 8095 and not port 9000 and not port 9200 and not port 9300 and not port 12201 and not port 514"
```

Значение с пробелами обязательно бери в кавычки целиком, вместе с именем переменной: systemd разделяет присваивания в `Environment=` по пробелам.

## Хранение

- Задачи захвата старше `capture.retention_days` (по умолчанию 7 дней) удаляются вместе с PCAP раз в час.
- Задачи с итогом «Компрометация» не удаляются автоматически, пока их не удалят вручную.
- Пустые интервалы (файл без пакетов) отбрасываются сразу.

## Права на файлы

tcpdump в rootful-контейнере создаёт файлы от root с правами `0644`. Веб-контейнер работает rootless от имени пользователя и переносит их в каталог задачи. Для этого нужно, чтобы каталог `spool/` и его подкаталог `ready/` принадлежали пользователю. Оба создаются командой `mkdir` выше, до первого запуска захвата.

## Ограничения

Хост видит только свой трафик и широковещательный. Чтобы анализировать трафик всей сети, нужен SPAN/зеркальный порт на коммутаторе или захват на маршрутизаторе с последующей загрузкой PCAP через веб-интерфейс.
