# USAGA Tools��0.1.0-rc1��

���� **PS2 �հ桶Unlimited SaGa��SLPS-25199** ����������ȡ���ַ����롢���븲�Ǻ�����д���о����ߡ���֧���Ѻ�����հ��޶�����֧�����桢ŷ�桢�����޶������� PS2 ��Ϸ��

���ֿ��������Դ�룬������Ϸ ISO/ELF��ԭʼͼƬ����Ϸ���֡��˹��ֱ������ġ����塢BIOS���浵���ڴ���ա�**���� MIT ����֤����Ȩ�����Ǳ���Ŀ���й���Դ����ĵ���**

## ������Ŀ¼

Python 3.10+��Ĭ��������ñ�׼�⡣`font-build` ��ʵ���� `lay-preview` ��ѡ���� Pillow��ʹ�õ� API Ҫ�� Pillow 10+��������������������û���Զ���װ�����ء�������ģ���������ȫ�����ò�����

���� `config.example.json` Ϊ˽�� `config.json`���޸� `work_dir` Ϊ�Լ�ѡ��Ĺ���Ŀ¼��Windows �½�ֹ���� C �̣������е�����·������� `work_dir`��Ҳ��д��Ŀ¼�ڵľ���·��������׼���Ϸ����е��հ���Ϸ�ļ����˹��ַ�ӳ������Ȩʹ�õ����塣˽�����ò�Ҫ�ύ��

```text
USAGA_Work/
  input/game.iso
  input/SLPS_251.99
  input/glyph_map.csv
  input/localization_font.ttf       # ��ѡ
  vendor/PIL/...                    # ��ѡ Pillow���û������ṩ
  _temp/ _cache/ _logs/             # �����Զ�����
```

�ֱ� CSV �������� `glyph_index,character`��ÿ�б��Ψһ��ÿ���ַ�ǡ��һ�� Unicode �ַ��������κ��Զ�ʶ��ԭ����Ϊ 0�C1763�����벻���δ֪��Ű��ﾳ�³�ĳ�����֡���չ�ֱ��ɹ���������ʹ�ã����ȶ�д����ڲ��Զ�������չ���롣

��Դ��Ŀ¼ִ�У��Ƽ�������������ֹ Python site ������ֽ��뻺����룺

```powershell
python -I -B -S usaga.py --help
python -I -B -S usaga.py --config config.json inspect-elf --out exports/elf
python -I -B -S usaga.py --config config.json extract-text --out exports/text
python -I -B -S usaga.py --config config.json extract-gra --out exports/gra
python -I -B -S usaga.py --config config.json extract-mapc --offset 0x4ADEB720 --length 0x9900 --out exports/mapc-menu
python -I -B -S usaga.py --config config.json scan-tim2 --out exports/tim2 --export
python -I -B -S usaga.py --config config.json font-build --out fonts/test --size 22
```

���Ŀ¼�������µ�Ŀ¼�����򲻻Ḳ�Ǿ������Ҳ���� `extract-text --banks 17,TONO5` �� `extract-gra --indices 5,6,7` �޶���Χ��

## ���롢���Ǽ��������д��

��ȡ�������ʮ���ƺ�ʮ������ ISO ƫ�ơ��ֽڳ��ȡ�ԭʼ����ͽ����������ư���ʵָ������飻˵����ָ��ָ��Ľű�����ʾָ����顣��¼˵����ȫ���������ã���������뿴����ͬ����һ���ı���������������������ʱ�����Ƿ�ȷ���������£���������ĵ���

��Ҫ����ı������� `���ķ���` �У����� `iso_offset,byte_length,text,raw_hex`��`translation_zh` Ҳ���ݡ����Ǽ��ֻ����ȫ��ͬ��ԭʼ����̳�Ψһ���ģ���ͻ���²⣺

```powershell
python -I -B -S usaga.py --config config.json coverage --occurrences exports/text/all_text_occurrences.csv --translations translations --out audits/coverage
python -I -B -S usaga.py --config config.json plan-text --csv translations/names.csv --out plans/names
python -I -B -S usaga.py --config config.json apply-plan --plan plans/names/patch_plan.json --out builds/names
```

**`plan-text` Ŀǰֻ�滮��֤ʵ����ָ����ڡ��� 01 �����ҿ��������ĵ�ԭ������ַ�����** ���ַ����������ĺ�δ֤���Ľű����־���ȷ����������д���ģ�����ָ�롣`apply-plan` ֻ������һ���ȳ� ISO����������ƥ��ԭ�� SHA-256 �Ͳ���ǰ�ֽڣ�ͨ���ص���鼰����ض��������ؽ� ISO9660�����ƶ���Դ�������ڵ�ǰ˽����Ŀ��ȫ�����Ĺ�������

`font-build` ���ɹ̶����ߡ�24��24 �ָ�42 �е��ֿ�ҳ PNG �� 4bpp ���ݣ�����ÿ���ֵİ�Χ�зֱ���У��������������ء������ָ��ܾ�����Ҫ��ʽ���ֺš����������ԭ�� TIM2/GRA ���������ֱ���滻����չ�ֿ���ء���ʾ��������Դ�ض�λ����������֤��

## Դ��㼶�뵱ǰ�߽�

| ·�� | ���� | ��λ |
|---|---|---|
| `usaga_tools/` | ���á�ELF��ԭ����롢�ű�ͼ��ͼƬ�����Ǽ�顢���޲����ƻ� | �ɶ���������� |
| `usaga_tools/experimental/` | MIPS �����/��������˫ҳ���塢�־��뻻�С����ڸ��롢����������ָ��� LAY ��ɫԤ�� | �հ��о����ܣ����������Զ����� |
| `research/README.md` | ˽�й�����δ���빫��Դ���ԭ�� | ���Ǩ������ |
| `docs/` | ��ʽ���ݡ���֤״̬��Ǩ��ȱ�ڡ���Դ�빫����Χ | �������� |
| `tests/` | ���ϳ������ı߽硢���롢ͼ����д�ز��� | ��������Ϸ�ʲ� |

�����ڡ�ȫ��Ϸ�ѵ����������� UI/����ʵ����֤ͨ�����ĳ�ŵ���ű�ͼ����δ����ָ�TIM2 �ṹ��֤����֤��λ��ȷΪ�����ļ���Ҳ��֤������ͼƬ�������������洢����ѡ��ʧ��λ�õ�����������ǰ�û���Ŀ��ȫ�����ġ��ֱ���ʵ��״̬���ᱻ���Դ��������滻��

## MAPC �˵����ɫԤ��

ʵ�ʲ˵���һ�������� MAPC ��Դ����ͬ�� GRA ͼƬ����֤����ǰ����ʹ�á�`extract-mapc` ֻ��������ȷ�ϵ� `mapc_tm2` ������128 �ֽ�ͷ��1024 �ֽڵ�ɫ�塢�ٺ�������������ء������Ѿ� GRA ������/��ɫ��˳�����õ� MAPC��Ҳ���Զ��ط�˵�ͼƬ��

```powershell
python -I -B -S usaga.py --config config.json lay-preview --out exports/lay
```

ʵ����Ԥ����Ĭ�϶�ȡ GRA 2900�C2906����ԭ������ָ��ѡ����ͼҳ��֡��������������ߴ򿪵� `index.html`��֡ PNG ������Ԫ���ݡ�621 ��ԭʼ֡�У�541 ֡�ɴӻ�������ȷ����ͼҳ������ 80 ֡����ҳ�š����ṩ��ά��������������������δ����������Ϸ����������任����ȡ�GS ����������ʱ���ʣ���������άģ�ͻ�����������ٶ���ȷΪԤ�����ã����ܵ��ɾ�ȷ��Ϸʱ����� [LAY �� MAPC](docs/LAY_AND_MAPC.md)��

## д��߽������

���������� TEMP/TMP/TMPDIR��`tempfile.tempdir`��Python/Pillow ��ػ��浽����Ŀ¼��Python ��ƹ��Ӿܾ�Ŀ¼��д����ⲿ���̣�����¼ȫ��ʵ��д��·�����ñ��������ڱ����� Python ���̣���������Լ������ϵͳ���ⲿ�༭�������� Python ��������������Ƽ� `-I -B -S`�����Զ����� Git��pip��Java ��ģ������

����ʱָ��һ�������ķ� C ��Ŀ¼����ʹ����ʵ��Ϸ��

```powershell
$env:USAGA_TEST_WORK='F:\USAGA_Test_Work'
python -I -B -S tests/run_tests.py
```

��ѡ���� `USAGA_TEST_PILLOW_DIR` Ϊ�Լ�׼���� Pillow ��Ŀ¼��ִ��͸������ƴ�Ӳ��ԡ����ֱ���ʵ��ִ�� 15 ����ԣ�ȫ��ͨ�������� GitHub Actions ���úϳ����ݣ�Զ����δ���С���֤����� [VALIDATION](docs/VALIDATION.md)�����ϴ�������Ĳ���� [CHANGELOG](docs/CHANGELOG.md)��

������Χ��������¼������Ǩ�����ݼ� [��������](docs/RELEASE_REVIEW.md)��
