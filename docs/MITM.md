# 用中间人代理记录 HTTPS 内容，再交给 Stakeout 读取

## 这条路线做什么

Stakeout 有两种方式看到加密连接里的内容：

1. `run --decrypt`：在手机上用 eCapture 记下应用通过系统 TLS 库（Conscrypt 的 `libssl.so`）建立加密连接时的密钥，采集结束后在电脑上用 Wireshark 的 `tshark` 解开抓到的数据包，不需要证书。它只解得开经过系统 TLS 库、而且在采集期间建立的连接；应用自带的 TLS 库（例如小红书的 Cronet 和它的长连接库）建立的连接没有密钥，它解不开。
2. 本文讲的路线：你自己在电脑上运行中间人代理（mitmproxy），让手机的 HTTPS 连接经过它。代理用自己的证书和应用握手，把请求和响应记下来，导出成 HAR 文件，Stakeout 读取这个文件。应用不用系统 TLS 库时，只要它按系统代理设置联网、信任系统证书库、没有做证书固定，这条路线就能记下它的内容。

两条路线可以同时用，报告里每条内容都标明来源。

**下面每一步都由你自己操作。Stakeout 不做其中任何一步：它不安装证书，不改手机的代理或任何其他设置，也不启动代理。它只读取你导出的 HAR 文件**（`python3 stakeout.py analyze <运行目录> --har 文件.har`）。

## 需要什么

- 已 root 的 Android 14 或 15 手机，root 方案能加载模块（例如 Magisk、KernelSU）。
- 一台电脑，和手机连在同一个 Wi-Fi 上。电脑的防火墙要允许手机连到代理端口（下面用 8080）。
- 电脑上装好 mitmproxy（从 mitmproxy 官网下载，或 `pipx install mitmproxy`）。导出 HAR 要用它的 `hardump` 选项：`mitmdump --options` 的输出里有 `hardump`，说明你的版本支持。
- openssl（macOS 自带）。

## 第 1 步：在电脑上启动代理

```
mitmweb --listen-port 8080 --set hardump=xhs.har
```

- `mitmweb` 会在浏览器里打开一个页面，实时列出经过代理的请求。不需要页面时用 `mitmdump`，参数相同。
- `hardump=xhs.har`：代理退出时（在这个终端按 Ctrl+C）把记录到的全部请求写成当前目录下的 `xhs.har`。**不正常退出（直接关掉终端、电脑断电）就不会写出这个文件。**
- 第一次启动时，mitmproxy 在 `~/.mitmproxy/` 生成自己的 CA：`mitmproxy-ca-cert.pem`（证书，下一步装到手机上）和 `mitmproxy-ca.pem`（含私钥，留在电脑上，不要给别人）。

## 第 2 步：把代理的 CA 证书放进手机的系统证书库

为什么必须是系统证书库：

- 装成“用户证书”不够。从 Android 7 起，应用默认只信任系统证书，除非应用自己声明信任用户证书，而绝大多数应用不声明。
- 从 Android 14 起，系统 CA 证书来自 Conscrypt 的 APEX 模块，目录是 `/apex/com.android.conscrypt/cacerts`。这个目录只读；把证书复制到以前的 `/system/etc/security/cacerts` 不再起作用。所以需要一个 root 模块，在开机时把证书放进这个目录，让应用进程看到。

操作：

1. 算出证书在系统证书目录里的文件名。文件名是证书主题的旧式哈希加 `.0`：

   ```
   openssl x509 -inform PEM -subject_hash_old -noout -in ~/.mitmproxy/mitmproxy-ca-cert.pem
   cp ~/.mitmproxy/mitmproxy-ca-cert.pem <输出的哈希>.0
   ```

2. 在 Magisk 或 KernelSU 里装一个“把 CA 证书加入系统证书库”的模块。选的时候看它的说明，必须写明支持 Android 14 及以上（也就是处理 `/apex/com.android.conscrypt/cacerts`）；只改 `/system/etc/security/cacerts` 的旧模块在这台手机上无效。
3. 按模块的说明放入证书。有的模块要求先把证书装成用户证书（把 `mitmproxy-ca-cert.pem` 传到手机上，在系统设置里搜索“证书”，选择安装 CA 证书），开机时由模块复制进系统证书库；有的要求把上面的 `<哈希>.0` 文件放进模块的目录。
4. 重启手机。

是否生效，在第 3 步设好代理以后看：mitmweb 页面里出现了应用 HTTPS 请求的内容，就是生效了。如果 mitmproxy 的日志显示客户端 TLS 握手失败、客户端不信任代理的证书，要么证书没有进系统证书库，要么这个应用做了证书固定（见“做不到的事”）。

## 第 3 步：在手机上设置代理

1. 查电脑在这个 Wi-Fi 里的 IP 地址（例如 `192.168.1.20`）。
2. 在手机的 WLAN 设置里打开当前网络的详情，把代理改为“手动”，主机名填电脑的 IP，端口填 `8080`，保存。

也可以在电脑上用 adb 设置（对所有网络生效）：

```
adb shell settings put global http_proxy <电脑的IP>:8080
```

## 第 4 步：采集并导出

1. 电脑上代理已在运行（第 1 步），手机代理已设好（第 3 步）。
2. 开始 Stakeout 采集：`python3 stakeout.py run <包名>`（可以同时加 `--decrypt`）。
3. 在手机上正常使用这个应用。
4. 按回车结束 Stakeout 的采集。
5. 在代理的终端按 Ctrl+C 退出，这时写出 `xhs.har`。
6. 让 Stakeout 读取它：

   ```
   python3 stakeout.py analyze <运行目录> --har xhs.har
   ```

   Stakeout 把这个文件复制到运行目录，名为 `mitm.har`；以后再对这个运行目录运行 `analyze`，会自动用它。

读结果时要知道：

- 代理记录的是手机上所有经过它的连接，不只是你要看的应用。HAR 里没有“哪个应用发的请求”这一项，Stakeout 也无法区分。采集期间不要使用别的应用；系统服务在后台的请求仍会混在里面。
- HAR 里时间不在这次 Stakeout 采集范围内的条目，报告会标明它们不在采集时间内。
- HAR 把正文存成文本时，如果原始内容没有声明字符集、文本里又有非 ASCII 字符，就无法确定原来发送的字节。这样的正文在报告里标为未解码，并写明原因。以 base64 保存的正文不受影响。

## 用完后恢复（每一步怎么撤销）

按下面的顺序做：

1. **手机代理**：在 WLAN 设置里把代理改回“无”；用 adb 设置过的，运行 `adb shell settings put global http_proxy :0`。先做这一步，再关电脑上的代理；否则手机上按代理联网的应用会连不上网。
2. **证书**：在 Magisk 或 KernelSU 里停用并删除那个模块，重启手机。装过用户证书的，在系统设置的“受信任的凭据”里，从“用户”一栏删除 mitmproxy 的证书（菜单位置因厂商而异，可以在设置里搜索“凭据”）。
3. **电脑上的 CA**：`~/.mitmproxy/mitmproxy-ca.pem` 里是 CA 的私钥。证书留在手机系统证书库期间，拿到这个私钥的人可以解密这台手机的 HTTPS 连接。手机上删掉证书以后，可以删除 `~/.mitmproxy/` 整个目录；下次启动 mitmproxy 会生成新的 CA。
4. **HAR 文件**：`xhs.har`、运行目录里的 `mitm.har` 和 `result.json` 都存有完整的 Cookie、登录凭据、请求和响应内容，没有遮盖。不再需要时删除它们，也不要发给别人。报告 `report.html` 默认隐藏凭据、签名、设备标识这类值（规则见 README 的“报告隐藏哪些值”，加 `--show-secrets` 才显示），但正文里的其他文字和二进制正文的十六进制照原样显示，所以报告里也可能有个人信息，转给别人之前要自己看一遍。

## 这条路线做不到的事

- **证书固定（certificate pinning）**：应用只接受它预先指定的证书或公钥时，代理的证书通不过检查，TLS 握手失败。这个连接的内容不会出现在 HAR 里，应用的相应功能在代理期间可能用不了。Stakeout 不绕过证书固定。
- **非 HTTP 协议**：应用自己的长连接协议、MQTT 等不是 HTTP 的连接，不会以请求的形式出现在 HAR 里，Stakeout 也就看不到其内容。
- **不经过代理的连接**：应用不按系统代理设置联网（直接连服务器），或者用基于 UDP 的 QUIC（HTTP/3），这些连接不经过代理，HAR 里没有。
- **WebSocket**：HAR 里只有建立 WebSocket 连接的那次请求；Stakeout 这一版不解析之后的 WebSocket 消息。
