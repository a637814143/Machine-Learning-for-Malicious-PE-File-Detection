# 恶意 PE 文件检测报告

- **生成时间**: 2025-11-30 21:46:50
- **文件名**: `Ransomware.CryptoLocker.exe`
- **文件路径**: `C:\Python Projects\Machine-Learning-for-Malicious-PE-File-Detection-main\data\pefile\malware\Ransomware.CryptoLocker.exe`
- **模型文件**: `C:\Python Projects\Machine-Learning-for-Malicious-PE-File-Detection-main\data\model\model.txt`

## 预测结果

- 模型判定: **恶意**
- 恶意概率 (展示): **66.5031%**
- 原始模型得分: 0.160105
- 判定阈值: 0.0385
- 检测模式: 高精度 (阈值 0.0385，对恶意程序容忍度一般，误判概率小)
- 检测结论: 该程序大概率是恶意程序！

## 模型信心与风险评估

- 综合风险等级: **高风险**
- 综合风险得分: **6.7 / 10**
- 判定信心: **中等** (与阈值差距 0.1216)

| 主要恶意信号 | 贡献分值 | 说明 |
| --- | --- | --- |
| 高风险 API 调用 | 2.95 | 命中 5 个高风险 API，可能具备注入、下载或加密能力。 |
| 节区熵值异常 | 1.30 | 检测到 1 个高熵节区，疑似包含压缩或加密载荷。 |
| 缺少数字签名 | 1.20 | 文件未发现 Authenticode 签名，可信度下降。 |
| 导入函数数量异常 | 0.80 | 导入函数总数达到 259，远高于常规应用平均水平。 |
| 编译时间异常 | 0.40 | PE 头部时间戳为 0，可能被篡改以规避检测。 |

**潜在缓解因素**

- 常见系统 API: 大量导入 85 个 GUI/系统相关 API，符合常见应用行为。

## 判定依据

模型认为该文件可能为恶意样本。
- 综合风险评估为 高风险 (得分 6.7/10)。
- 导入了高风险 API：ADVAPI32.dll!RegSetValueExW, ADVAPI32.dll!CryptImportKey, ADVAPI32.dll!CryptEncrypt, ADVAPI32.dll!RegCreateKeyExW, SHELL32.dll!ShellExecuteExW。
- 存在高熵节区，可能包含压缩或加密代码：.rsrc (熵 7.97)。
- 缺少数字签名，降低可信度。
- 字符串中包含 13 个 URL 片段，疑似具备网络通信能力。

## 文件特征概览

- 文件大小: 346112 字节
- 虚拟大小 (SizeOfImage): 356352
- 是否包含数字签名: 否
- 导入函数数量: 259
- 字符串熵: 6.36
- URL 字符串数量: 13
- 注册表字符串数量: 0
- 字符串密度: 11.68 条/KB
- 节区数量: 5
- 入口节区: 未知

## PE 头部信息

- 机器类型: I386
- 编译时间: 未知/异常 (时间戳为 0)
- 子系统: WINDOWS_GUI
- 代码区大小: 64512
- 头部大小: 1024
- COFF 标志: EXECUTABLE_IMAGE, NEED_32BIT_MACHINE

## 高风险 API

- `ADVAPI32.dll!RegSetValueExW`: 修改注册表键值，可能用于持久化。
- `ADVAPI32.dll!CryptImportKey`: 导入密钥，可能用于自定义加密流程。
- `ADVAPI32.dll!CryptEncrypt`: 使用 CryptoAPI 进行加密，可能隐藏通信内容。
- `ADVAPI32.dll!RegCreateKeyExW`: 创建注册表键值，可能用于持久化。
- `SHELL32.dll!ShellExecuteExW`: 通过 ShellExecute 执行系统命令。

## 高熵节区

- `.rsrc` — 大小 253952 字节，熵 7.97

## 常见系统 API

- `USER32.dll!MessageBoxIndirectW`
- `USER32.dll!InSendMessage`
- `USER32.dll!ClientToScreen`
- `USER32.dll!GetWindowLongW`
- `USER32.dll!GetClassNameW`
- `USER32.dll!GetCaretPos`
- `USER32.dll!TrackPopupMenu`
- `USER32.dll!AppendMenuW`
- `USER32.dll!GetCursorPos`
- `USER32.dll!CreatePopupMenu`

## 字符串统计

- 可打印字符串数量: 27927
- 平均字符串长度: 7.08
- MZ 标记次数: 5

### URL 样本

- http://en.wikipedia.org/wiki/RSA_%28algorithm%29"}}{\fldrslt{RSA-2048}}}\cf1\ulnone\b0\f0\fs20
- https://www.moneypak.com/StoreLocator.aspx"
- https://www.moneypak.com/"}}{\fldrslt{\ul
- https://www.moneypak.com/StoreLocator.aspx"}}{\fldrslt{\ul
- https://www.ukash.com/en-GB/registration/"}}{\fldrslt{\cf3\ul\b
- Ukash.com,
- https://www.ukash.com/en-GB/"}}{\fldrslt{\ul
- https://www.ukash.com/en-GB/where-to-get/"}}{\fldrslt{\ul
- https://www.cashu.com/"}}{\fldrslt{\ul
- https://www.cashu.com/site/en/fundcashU"}}{\fldrslt{\ul

### IP 地址样本

- 6.0.0.0

### 可疑文件路径样本

- \\S#\SM%5.ٰ=JhSڵy74
- I:\Q
- \\\`2l4H
- X:\

### 最长字符串样本

- \viewkind4\uc1\pard\sl240\slmult1\cf1\lang9\f0\fs20 cashU is a prepaid online and mobile payment method available in the Middle East and North Africa, a region with a large and young population with very limited access to credit cards. Because of this, cashU has become one of the most popular alternative payment option for young Arabic online gamers and e-commerce buyers.\cf0\par
- You can \b combine multiple values\b0  of your Ukash into a single amount and have your new Ukash Code and value emailed to you if you want. You will need to {\field{\*\fldinst{HYPERLINK "https://www.ukash.com/en-GB/registration/"}}{\fldrslt{\cf3\ul\b register}}}\cf1\ulnone\b0\f0\fs20  at Ukash.com, login and then go to the Manage Ukash area to use the Combine tool.\par
- \viewkind4\uc1\pard\nowidctlpar\cf1\lang9\f0\fs20 Bitcoin is a cryptocurrency where the creation and transfer of bitcoins is based on an open-source cryptographic protocol that is independent of any central authority. Bitcoins can be transferred through a computer or smartphone without an intermediate financial institution.\par
- MoneyPak can be purchased at thousands of stores nationwide, including major retailers such as Walmart, Walgreens, CVS/pharmacy, Rite Aid, Kmart and Kroger. Click {\field{\*\fldinst{HYPERLINK "https://www.moneypak.com/StoreLocator.aspx" }}{\fldrslt{\cf3\ul\b here}}}\cf1\ulnone\b0\f0\fs20  to find a store near you.\par
- \viewkind4\uc1\pard\nowidctlpar\cf1\lang9\f0\fs20 Your important files \b encryption\b0  produced on this computer: photos, videos, documents, etc. \cf2\ul\b{\field{\*\fldinst{HYPERLINK "viewfiles"}}{\fldrslt{Here}}}\cf1\ulnone\b0\f0\fs20  is a complete list of encrypted files, and you can personally verify this.\par
- Encryption was produced using a \b unique\b0  public key \cf2\ul\b{\field{\*\fldinst{HYPERLINK "http://en.wikipedia.org/wiki/RSA_%28algorithm%29"}}{\fldrslt{RSA-2048}}}\cf1\ulnone\b0\f0\fs20  generated for this computer. To decrypt files you need to obtain the \b private key.\par
- The \b single copy \b0 of the private key, which will allow you to decrypt the files, located on a secret server on the Internet; the server will \b destroy\b0  the key after a time specified in this window. After that, \b nobody and never will be able\b0  to restore files...\par
- You have to send below specified amount to Bitcoin address \b{\field{\*\fldinst{HYPERLINK "bitcoin:%BITCOIN_ADDRESS%?amount=%AMOUNT_BTC%"}}{\fldrslt{%BITCOIN_ADDRESS%}}}\b0\f0\fs20  and specify the transaction ID, which will be verified and confirmed.\par
- Money can be purchased from one of the reported 420,000 participating retail locations worldwide, or by using the company\rquote s website. This electronic money can then be used to pay online, or loaded on to a prepaid card or eWallet.\par
- \b To obtain\b0  the private key for this computer, which will automatically decrypt files, you need to pay \b %AMOUNT_USD% USD\b0  / \b %AMOUNT_EUR% EUR\b0  / similar amount in another currency.\par

### 高频字符分布

| 字符 | 计数 |
| --- | ---: |
| `e` | 1184 |
| `t` | 872 |
| ` ` | 784 |
| `r` | 689 |
| `o` | 668 |
| `a` | 663 |
| `n` | 648 |
| `i` | 617 |
| `l` | 605 |
| `\` | 528 |

## 节区分布概览

| 节区 | 大小 (字节) | 虚拟大小 | 熵 | 关键特征 |
| --- | ---: | ---: | ---: | --- |
| `.rsrc` | 253952 | 0 | 7.97 | 无 |
| `.text` | 64512 | 0 | 6.36 | 无 |
| `.rdata` | 17920 | 0 | 4.88 | 无 |
| `.reloc` | 8192 | 0 | 4.98 | 无 |
| `.data` | 512 | 0 | 2.10 | 无 |

## 导入 DLL 统计

| DLL | 导入函数数量 |
| --- | ---: |
| KERNEL32.dll | 79 |
| USER32.dll | 73 |
| ADVAPI32.dll | 25 |
| gdiplus.dll | 25 |
| GDI32.dll | 12 |
| SHLWAPI.dll | 12 |
| WINHTTP.dll | 10 |
| msvcrt.dll | 7 |
| SHELL32.dll | 4 |
| ole32.dll | 4 |
| COMCTL32.dll | 3 |
| CRYPT32.dll | 3 |
| UxTheme.dll | 1 |
| MSIMG32.dll | 1 |

## 数据目录概览

| 数据目录 | 大小 | RVA |
| --- | ---: | ---: |
| IMPORT_TABLE | 300 | 81340 |
| RESOURCE_TABLE | 253816 | 94208 |
| BASE_RELOCATION_TABLE | 4900 | 348160 |
| IAT | 1092 | 69632 |

## 哈希信息

- SHA-256: `d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9`
- MD5: `04fb36199787f2e3e2135611a38321eb`
