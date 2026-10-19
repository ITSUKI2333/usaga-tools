# USAGA Tools（0.1.0-rc1）

面向 **PS2 日版《Unlimited SaGa》SLPS-25199** 的命令行提取、字符编码、翻译覆盖核验与写回研究工具。仅支持已核验的日版修订，不支持美版、欧版、其他修订或任意 PS2 游戏。

本仓库包含工具源码，不含游戏 ISO/ELF、原始图片、游戏文字、人工字表、译文、字体、BIOS、存档或内存快照。**采用 MIT 许可证；授权仅覆盖本项目自有工具源码和文档。**

## 环境和目录

Python 3.10+；默认命令仅用标准库。`font-build` 和实验性 `lay-preview` 可选依赖 Pillow（使用的 API 要求 Pillow 10+），其他命令无需它。没有自动安装、下载、联网、模拟器输入或全局配置操作。

复制 `config.example.json` 为私用 `config.json`，修改 `work_dir` 为自己选择的工作目录。Windows 下禁止设在 C 盘；配置中的输入路径均相对 `work_dir`，也可写该目录内的绝对路径。自行准备合法持有的日版游戏文件、人工字符映射与有权使用的字体。私用配置不要提交。

```text
USAGA_Work/
  input/game.iso
  input/SLPS_251.99
  input/glyph_map.csv
  input/localization_font.ttf       # 可选
  vendor/PIL/...                    # 可选 Pillow，用户自行提供
  _temp/ _cache/ _logs/             # 程序自动创建
```

字表 CSV 最少两列 `glyph_index,character`，每行编号唯一，每个字符恰好一个 Unicode 字符；不含任何自动识别。原版编号为 0–1763。解码不会把未知编号按语境猜成某个汉字。扩展字表可供字体生成使用，但稳定写回入口不自动启用扩展编码。

从源码目录执行，推荐隔离启动，防止 Python site 插件和字节码缓存介入：

```powershell
python -I -B -S usaga.py --help
python -I -B -S usaga.py --config config.json inspect-elf --out exports/elf
python -I -B -S usaga.py --config config.json extract-text --out exports/text
python -I -B -S usaga.py --config config.json extract-gra --out exports/gra
python -I -B -S usaga.py --config config.json extract-mapc --offset 0x4ADEB720 --length 0x9900 --out exports/mapc-menu
python -I -B -S usaga.py --config config.json scan-tim2 --out exports/tim2 --export
python -I -B -S usaga.py --config config.json font-build --out fonts/test --size 22
```

输出目录必须是新的目录，程序不会覆盖旧输出。也可用 `extract-text --banks 17,TONO5` 或 `extract-gra --indices 5,6,7` 限定范围。

## 翻译、覆盖检查与有限写回

提取结果包含十进制和十六进制 ISO 偏移、字节长度、原始编码和解码结果。名称按真实指针表分组；说明按指针指向的脚本及显示指令分组。记录说明表全部别名引用，避免仅翻译看似相同的另一份文本。表级中文语义与运行时调用是否确认是两回事，详见技术文档。

在要翻译的表中添加 `中文翻译` 列；保留 `iso_offset,byte_length,text,raw_hex`。`translation_zh` 也兼容。覆盖检查只对完全相同的原始编码继承唯一译文，冲突不猜测：

```powershell
python -I -B -S usaga.py --config config.json coverage --occurrences exports/text/all_text_occurrences.csv --translations translations --out audits/coverage
python -I -B -S usaga.py --config config.json plan-text --csv translations/names.csv --out plans/names
python -I -B -S usaga.py --config config.json apply-plan --plan plans/names/patch_plan.json --out builds/names
```

**`plan-text` 目前只规划可证实名称指针表内、以 01 返回且可容纳译文的原版编码字符串。** 新字符、超长译文和未证明的脚本文字均明确跳过，不缩写译文，不猜指针。`apply-plan` 只生成另一个等长 ISO；必须完整匹配原版 SHA-256 和补丁前字节，通过重叠检查及输出回读。它不重建 ISO9660、不移动资源，不等于当前私有项目的全量中文构筑器。

`font-build` 生成固定基线、24×24 字格、42 列的字库页 PNG 和 4bpp 数据；不按每个字的包围盒分别居中，不缩放字形像素。超过字格会拒绝，需要显式调字号。输出还不是原生 TIM2/GRA 封包，不能直接替换。扩展字库加载、显示度量及资源重定位必须配套验证。

## 源码层级与当前边界

| 路径 | 内容 | 定位 |
|---|---|---|
| `usaga_tools/` | 配置、ELF、原版编码、脚本图、图片、覆盖检查、有限补丁计划 | 可独立运行入口 |
| `usaga_tools/experimental/` | MIPS 汇编器/解释器、双页字体、字距与换行、窗口隔离、别名、溢出恢复和 LAY 角色预览 | 日版研究功能；补丁不会自动启用 |
| `research/README.md` | 私有构筑链未纳入公开源码的原因 | 入口迁移限制 |
| `docs/` | 格式依据、验证状态、迁移缺口、来源与公开范围 | 审批材料 |
| `tests/` | 纯合成样本的边界、编码、图形与写回测试 | 不包含游戏资产 |

不存在“全游戏已导净”“所有 UI/语音实机验证通过”的承诺。脚本图仍有未解析指令；TIM2 结构验证不保证该位置确为独立文件，也不证明所有图片采用线性纹理存储。候选和失败位置单独导出。当前用户项目的全部译文、字表和实机状态不会被这个源码包悄悄替换。

## MAPC 菜单与角色预览

实际菜单有一条独立的 MAPC 资源链；同名 GRA 图片不保证被当前界面使用。`extract-mapc` 只读导出已确认的 `mapc_tm2` 容器：128 字节头、1024 字节调色板、再后面才是索引像素。它不把旧 GRA 的像素/调色板顺序套用到 MAPC，也不自动回封菜单图片。

```powershell
python -I -B -S usaga.py --config config.json lay-preview --out exports/lay
```

实验性预览器默认读取 GRA 2900–2906，按原生动作指令选择贴图页与帧。输出包含可离线打开的 `index.html`、帧 PNG 和逐项元数据。621 个原始帧中，541 帧可从基础序列确定贴图页，余下 80 帧不猜页号。它提供二维部件画面和序列浏览，尚未完整复现游戏场景的整体变换、深度、GS 采样和运行时速率；不导出三维模型或骨骼。播放速度明确为预览设置，不能当成精确游戏时序。详见 [LAY 与 MAPC](docs/LAY_AND_MAPC.md)。

## 写入边界与测试

启动后设置 TEMP/TMP/TMPDIR、`tempfile.tempdir`、Python/Pillow 相关缓存到工作目录；Python 审计钩子拒绝目录外写入和外部进程，并记录全部实际写入路径。该保护作用于本工具 Python 进程，不能声称约束操作系统、外部编辑器或其他 Python 启动插件；所以推荐 `-I -B -S`，不自动调用 Git、pip、Java 或模拟器。

测试时指定一个独立的非 C 盘目录，不使用真实游戏：

```powershell
$env:USAGA_TEST_WORK='F:\USAGA_Test_Work'
python -I -B -S tests/run_tests.py
```

可选设置 `USAGA_TEST_PILLOW_DIR` 为自己准备的 Pillow 包目录，执行透明部件拼接测试。本轮本机实际执行 15 项测试，全部通过；附带 GitHub Actions 仅用合成数据，远端尚未运行。验证结果见 [VALIDATION](docs/VALIDATION.md)，与上次审批稿的差异见 [CHANGELOG](docs/CHANGELOG.md)。

公开范围、审批记录和仍需迁移内容见 [发布审批](docs/RELEASE_REVIEW.md)。
