

# Recent Papers/Blogs/Tools Related to Fuzzing
[<img src="logo/logo.png" align="right" width="30%">](https://github.com/liyansong2018/fuzzing-tutorial)

> Curated list of classic fuzzing books, papers about fuzzing at information security top conferences over the years, commonly used fuzzing tools, and resources that can help us use fuzzer easily. → [English](https://liyansong2018.github.io/fuzzing-tutorial/README_en)

本项目收录了经典的 fuzzing 书籍、历年安全顶会上有关 fuzzing 的经典论文、常用的 fuzzing 工具、可以快速入手 fuzzing 工具的博客，如果你有更多资源，欢迎贡献。

<hr />

## Table of Contents

- [1 Books](#1-Books)
- [2 Articles/Papers](#2-Articles/Papers)
  + [Others](#Others)
  + [NDSS](#NDSS)
  + [USENIX Security](#USENIX-Security)
  + [IEEE S&P](#IEEE-S&P)
  + [ACM CCS](#ACM-CCS)
- [3 Tools](#3-Tools)
  + [变异器](#变异器)
  + [二进制](#二进制)
  + [API/协议](#API/协议)
  + [固件](#固件)
- [4 Blogs](#4-Blogs)

## 1 Books

- [The Fuzzing Book](https://www.fuzzingbook.org/) (2019)：该书以原理+代码练习为基础，从 0 到 1 完成一个模糊测试框架，结合实际的练习，如果想编写自己的测试框架，可以参考本书。
- [Fuzzing for Software Security Testing and Quality Assurance](https://www.amazon.com/Fuzzing-Software-Security-Testing-Assurance/dp/1608078507/) (2018)：本书将模糊测试的思想引入软件开发生命周期，事实上很多高效的 fuzzing 测试往往在开发阶段就已经考虑到，该书探讨了 fuzz 工具的发展，不仅包括一些新兴开源工具，也涵盖诸多商用的 fuzzer，如何为软件开发项目选择合适的 fuzzer 也是本书的主题之一。

## 2 Articles&Papers

本章收录安全顶会和一些期刊上的经典论文，大而全不是我们的目的，只是想选择其中一些技术价值比较高或者比较新颖的文章，方便后续的学习。

### Others

- [The Art, Science, and Engineering of Fuzzing: A Survey](https://ieeexplore.ieee.org/document/8863940) (2019)：韩国科学技术研究院学者提出的一个通用 fuzz 模型，包含很多 fuzz 相关概念，在介绍 fuzz 技术的基础上，有一个包含 60+ fuzz 工具的对比，如果想知道更多 fuzz 工具，也许可以从该表中找到。
- [Fuzzing: a survey](https://cybersecurity.springeropen.com/articles/10.1186/s42400-018-0002-y) (2018)：清华大学相关机构发表在 [*Cybersecurity*](https://cybersecurity.springeropen.com/) 上的一篇关于 fuzzing 技术的调查。尽管论文中有一些值得商榷的描述，但是该论文可以让我们大概了解 fuzzing 历史、原理以及技术分类。
- [Evaluating Fuzz Testing, 2018](http://www.cs.umd.edu/~mwh/papers/fuzzeval.pdf)：美国马里兰大学学者在 CCS 2018 上的一篇论文，总结近些年 fuzzing 的发展，分析了安全顶会上提出的多个工具，涵盖了 fuzzing 完整的生命周期，是一篇不错的 survery。
- [Fuzzing: Art, Science, and Engineering, 2018](https://arxiv.org/pdf/1812.00140.pdf)：一个非常详尽的 survery，包括各个工具的对比，也涵盖了 fuzzing 的各个阶段。
- [Fuzzing: State of the art, 2018](https://ieeexplore.ieee.org/document/8371326)：国人发表在 [IEEE Transactions on Reliability](https://ieeexplore.ieee.org/xpl/RecentIssue.jsp?punumber=24)  上的论文，可以大概了解 fuzzing 思想，但是分析并不深入，相比上面两篇文章，有一定的差距。
- [Source-and-Fuzzing](https://github.com/lcatro/Source-and-Fuzzing) (2019)： 一些阅读源码和 fuzzing 的经验，涵盖黑盒与白盒测试，一系列文章对 fuzz 的分析较为深入，值得一看。
- [Effective File Format Fuzzing – Thoughts, Techniques and Results](https://www.youtube.com/watch?v=qTTwqFRD1H8) (Blackhat Europe 2015)：作者主要分享多年来对多个开源和商用软件的 fuzz 方法，包括 Adobe Reader、 Wireshark、 Hex-Rays IDA Pro 等软件。
- [CoLaFUZE: Coverage-Guided and Layout-Aware Fuzzing for Android Drivers](https://www.jstage.jst.go.jp/article/transinf/E104.D/11/E104.D_2021NGP0005/_pdf) (2021)，*南方电网数字电网研究院有限公司* 的 Tianshi Mu 等人介绍了CoLaFUZE，一个覆盖率引导和布局感知的模糊工具，用于自动生成有效输入和探索驱动程序代码。用于模糊测试**安卓驱动程序**。
- [Better Pay Attention Whilst Fuzzing](https://arxiv.org/pdf/2112.07143) (2022), 浙江大学 Shunkai Zhu 等人提出的 ATTuzz，用于解决现有 fuzzing 工具的两个局限性，缺乏对程序的全面分析和缺乏有效的变异策略。通过深度学习提高覆盖率。

### NDSS

#### 2023

- [Assessing the Impact of Interface Vulnerabilities in Compartmentalized Software, 2023](https://www.ndss-symposium.org/ndss-paper/assessing-the-impact-of-interface-vulnerabilities-in-compartmentalized-software/) - 针对上下文隔离的 API 接口（CIV，这是作者定义的一个概念，主要是指沙箱等隔离环境，应用划分、隔离后，应用的不同部分之间在交互时的控制和数据依赖关系，会在 interface 引入新的漏洞）进行 Fuzzing 的方案。Github 文档描述非常详细，[已开源](https://github.com/conffuzz/conffuzz)，当前作者已针对  Okular/ImageMagick/Apache/exif  等诸多软件进行了模糊测试。该项研究来自曼彻斯特大学。
- [FUZZILLI: Fuzzing for JavaScript JIT Compiler Vulnerabilities, 2023](https://www.ndss-symposium.org/ndss-paper/fuzzilli-fuzzing-for-javascript-jit-compiler-vulnerabilities/) - 谷歌Project Zero安全团队开发的针对 Javascript JIT 引擎进行 Fuzzing 的工具。[已开源](https://github.com/googleprojectzero/fuzzilli)。
- [No Grammar, No Problem: Towards Fuzzing the Linux Kernel without System-Call Descriptions, 2023](https://www.ndss-symposium.org/ndss-paper/no-grammar-no-problem-towards-fuzzing-the-linux-kernel-without-system-call-descriptions/) - 不用像 Syzkaller 那样编写复杂的系统调用描述，即可对内核进行 Fuzzing 的工具。[FuzzNG 已开源](https://github.com/BUseclab/FuzzNG)。
- [DARWIN: Survival of the Fittest Fuzzing Mutators, 2023](https://www.ndss-symposium.org/ndss-paper/darwin-survival-of-the-fittest-fuzzing-mutators/) - 来自于上海交通大学的文章，改进优化 AFL 变异算法，通过实验证明比原生 AFL 多出 66% 的安全漏洞，[已开源](https://github.com/TUDA-SSL/DARWIN)，很好奇为啥叫 DARWIN 的软件或者工具这么多🐶。
- [LOKI: State-Aware Fuzzing Framework for the Implementation of Blockchain Consensus Protocols, 2023](https://www.ndss-symposium.org/ndss-paper/loki-state-aware-fuzzing-framework-for-the-implementation-of-blockchain-consensus-protocols/) - 针对区块链共识协议实现模糊测试的方法，来自清华大学，未见开源。
- [OBSan: An Out-Of-Bound Sanitizer to Harden DNN Executables, 2023](https://www.ndss-symposium.org/ndss-paper/obsan-an-out-of-bound-sanitizer-to-harden-dnn-executables/) - 来自香港大学的研究，针对深度神经网络相关程序的模糊测试，请注意，并不是将神经网络应用在 Fuzzing 中，而是针对神经网络相关应用进行 Fuzzing，[已开源](https://github.com/yanzuochen/obsan)。

#### 2022

- [Semantic-Informed Driver Fuzzing Without Both the Hardware Devices and the Emulators](https://www.ndss-symposium.org/ndss-paper/auto-draft-248/) (2022): *西安交通大学* ，*赵文佳* 等人提出了一种无设备驱动程序模糊测试系统 DR .FUZZ，它不需要硬件设备对驱动程序进行 Fuzzing。DR .FUZZ 的核心是一种**语义通知机制**，它有效地生成输入以正确构造相关数据结构，以在驱动初始化时通过“验证链”，从而实现后续的无设备驱动程序模糊测试。 
- [MobFuzz: Adaptive Multi-objective Optimization in Gray-box Fuzzing](https://www.ndss-symposium.org/ndss-paper/auto-draft-199/) (2022) : 国防科技大学  提出了一种用于多目标优化 (MOO) 的灰盒模糊器，称为 MobFuzz。
- [FirmWire: Transparent Dynamic Analysis for Cellular Baseband Firmware](https://hernan.de/research/papers/firmwire-ndss22-hernandez.pdf) (2022) : 美国佛罗里达大学开发的工具 [FirmWire](https://github.com/FirmWire/FirmWire)，是一个支持三星和联发科的全系统**基带**固件分析平台。它支持对基带固件映像进行模糊测试、模拟和调试。
- [EMS: History-Driven Mutation for Coverage-based Fuzzing](https://nesa.zju.edu.cn/download/lcy_pdf_ems_ndss22.pdf) (2022): 浙江大学*吕晨阳*  提出的一种新颖的变异方案，通过分析历史测试用例，发现一些已经尝试过的用例仍有可能触发新的独特路径。提出了一种轻量级、高效的 Probabilistic Byte Orientation Model（PBOM）模型，基于此提出了一个新的历史驱动的变异框架 EMS，发现了多个新的 CVE。
- [Context-Sensitive and Directional Concurrency Fuzzing for Data-Race Detection](https://www.ndss-symposium.org/ndss-paper/auto-draft-198/) (2022) : 清华大学相关团队 开发了一个名为 CONZZER 的新型并发模糊测试框架，以有效地探索线程交错并检测难以发现的**数据竞争**。
- [datAFLow: Towards a Data-Flow-Guided Fuzzer](https://www.ndss-symposium.org/ndss-paper/auto-draft-273/) (2022):  *澳大利亚国立大学*  开发的 DATAFLOW，这是一个由轻量级数据流分析驱动的灰盒模糊器。

#### 2021

- [Favocado: Fuzzing the Binding Code of JavaScript Engines Using Semantically Correct Test Cases, 2021](https://www.ndss-symposium.org/ndss-paper/favocado-fuzzing-the-binding-code-of-javascript-engines-using-semantically-correct-test-cases/)：美国亚利桑那州立大学师生提出一种对 **JS 引擎**中绑定层代码进行 fuzzing 的工具：[Favocado](https://github.com/favocado/Favocado)。作者在对在4个不同的JavaScript运行时系统fuzz时，发现了61个新的bug，其中33个是安全漏洞，13个已经被CVE收录。
- [WINNIE : Fuzzing Windows Applications with Harness Synthesis and Fast Cloning, 2021](https://www.ndss-symposium.org/ndss-paper/winnie-fuzzing-windows-applications-with-harness-synthesis-and-fast-cloning/)： 利用合成和快速克隆对 **Windows 应用程序**进行模糊测试 ， *佐治亚理工学院* 的作者构建了一个端到端 [WINNIE](https://github.com/sslab-gatech/winnie) 系统，包含两个组件：可从二进制文件中自动合成工具的生成器，以及一个高效的 Windows forkserver。 对比工具： WinAFL 。
- [PGFUZZ: Policy-Guided Fuzzing for Robotic Vehicles, 2021](https://www.ndss-symposium.org/ndss-paper/pgfuzz-policy-guided-fuzzing-for-robotic-vehicles/)：普度大学 *Hyungsub Kim* 等人设计的一个针对机器车辆（ Robotic vehicles, RVs）fuzzing 工具，即 [PGFUZZ](https://github.com/purseclab/PGFUZZ)，应用场景较为有限。
- [Reinforcement Learning-based Hierarchical Seed Scheduling for Greybox Fuzzing, 2021](https://www.ndss-symposium.org/ndss-paper/reinforcement-learning-based-hierarchical-seed-scheduling-for-greybox-fuzzing/)： *加州大学河滨分校* 华人团队通过引入多级覆盖和设计了基于强化学习的分层调度器，保留更多有价值的种子。即更加细粒度衡量代码覆盖率和更加合理的种子调度策略。

#### 2020 ⤵ 

- [HFL: Hybrid Fuzzing on the Linux Kernel](https://www.unexploitable.systems/publication/kimhfl/) (2020)：美国[*俄勒冈州*立大学](https://www.baidu.com/link?url=sn1QvZgfhW08eCz3smcHQsKmxmvdxUVfs90iYf52Qk_F7JedSab1kMqjelKzllZ-P1N3hOHeNCA6tKlSfhfjRdKefUtwi5pzYrjN-fcKWKG&wd=&eqid=fda401e6000301af00000006604737c0)提出的一个新兴混合 fuzz 工具。据作者所属，HFL 代码覆盖率分别比 Moonshine 和 Syzkaller 高出15%和26%，并发现 20+ 个内核漏洞。该工具好像没有开源。
- [HotFuzz: Discovering Algorithmic Denial-of-Service Vulnerabilities Through Guided Micro-Fuzzing](https://www.researchgate.net/publication/339164746_HotFuzz_Discovering_Algorithmic_Denial-of-Service_Vulnerabilities_Through_Guided_Micro-Fuzzing) (2020)：美国波士顿大学开发的 HotFuzz，这是一个用于自动发现 Java 库中 AC （算法复杂性）漏洞框架 。
- [Not All Coverage Measurements Are Equal: Fuzzing by Coverage Accounting for Input Prioritization](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24422.pdf) (2020)：中科院软件所开发的  [TortoiseFuzz](https://github.com/TortoiseFuzz/TortoiseFuzz) ，设计了一种新的模糊输入优化方案，发现了 20+ 0 day 漏洞。
- [PeriScope: An Effective Probing and Fuzzing Framework for the Hardware-OS Boundary](https://people.cs.kuleuven.be/~stijn.volckaert/papers/2019_NDSS_PeriScope.pdf) (2019)：加州大学研发的一个名为 PeriScope 的 fuzz 工具，主要针对内核与硬件的边界部分，该工具好像没有开源。
- [INSTRIM: Lightweight Instrumentation for Coverage-guided Fuzzing](https://www.ndss-symposium.org/wp-content/uploads/2018/07/bar2018_14_Hsu_paper.pdf) (2018)：台湾大学，学术研究，探讨了覆盖导向模糊的轻量级检测方法。
- [IOTFUZZER: Discovering Memory Corruptions in IoT Through App-based Fuzzing](### 固件) (2018)：见固件章节。
- [What You Corrupt Is Not What You Crash: Challenges in Fuzzing Embedded Devices](http://s3.eurecom.fr/docs/ndss18_muench.pdf)：嵌入式固件 fuzzing 的一些难点，固件的 fuzz 往往得不到反馈，该论文基于Avatar 和 PANDA 设计了六种不同启发式算法，提高嵌入式系统 fuzz 效率。
- [Enhancing Memory Error Detection for Large-Scale Applications and Fuzz Testing](https://lifeasageek.github.io/papers/han:meds.pdf) (2018)：韩国科学技术研究院对内存错误检测算法的研究。
- [DELTA: A Security Assessment Framework for Software-Defined Networks](https://www.ndss-symposium.org/wp-content/uploads/2017/09/ndss201702A-1LeePaper.pdf) (2017)：韩国科学技术研究院对 SDN 设计的安全评估框架。

### USENIX Security

#### 2023

- [Fuzztruction: Using Fault Injection-based Fuzzing to Leverage Implicit Domain Knowledge, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/bars) -  *波鸿鲁尔大学*  Nils Bars，提出一种新颖的模糊测试方案，不是变异种子，而是根据源码中的编码含义，变异数据生成器，甚至是注入错误，绕过一些判断，以便输入的用例几乎是预期的格式。这样的数据绕过了初始解析。[工具原型已开源](https://github.com/fuzztruction/fuzztruction)，提供了 Docker 虚拟机环境，10G+，感兴趣的同学如果想尝试此工具，请注意预留足够的磁盘空间。
- [DynSQL: Stateful Fuzzing for Database Management Systems with Complex and Valid SQL Query Generation, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/jiang-zu-ming) -  *苏黎世联邦理工学院*  Zu-Ming Jiang，一个完全自动化的模糊测试框架 DynSQL，用于测试各种 DBMS 数据库管理系统。
- [FuzzJIT: Oracle-Enhanced Fuzzing for JavaScript Engine JIT Compiler, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wang-junjie) -  *天津大学*  Junjie Wang，针对 Javascript 引擎的 JIT 编译器的模糊测试工具。[FuzzJIT](https://github.com/SpaceNaN/fuzzjit)，已开源。
- [GLeeFuzz: Fuzzing WebGL Through Error Message Guided Mutation, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/peng) -  *普渡大学*  Hui Peng，WebGL 是一组用于 GPU 加速图形的标准化 JavaScript API，通过分析 Chrome 的 WebGL 实现以识别发出错误的语句之间的依赖关系和被拒绝的输入部分，并使用此信息来指导输入变异，这就是 [GLeeFuzz](https://github.com/HexHive/GLeeFuzz)，已开源。
- [Automata-Guided Control-Flow-Sensitive Fuzz Driver Generation, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/zhang-cen) -  *南洋理工大学*  Cen Zhang，提出了 RUBICK，这是一种自动引导的控制流敏感模糊驱动程序，公开资料较少，论文还未正式发布。
- [PolyFuzz: Holistic Greybox Fuzzing of Multi-Language Systems, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/li-wen) -  *华盛顿州立大学*  Wen Li，[POLYFUZZ](https://github.com/Daybreak2019/PolyFuzz)，已开源，这是一种灰盒模糊器，它通过跨语言覆盖反馈和跨语言（不同片段）程序输入和分支谓词之间的语义关系的显式建模，对给定的多语言系统进行整体模糊。POLYFUZZ 是可扩展的，支持以不同语言组合编写的多语言代码，例如 C、Python、Java。
- [AIFORE: Smart Fuzzing Based on Automatic Input Format Reverse Engineering, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/shi-ji) -  *中国科学院信息工程研究所*  Ji Shi，自动输入格式逆向工程代表了一种有吸引力但具有挑战性的学习格式的方法，而本文就是为了解决程序的输入格式，提出的一种名为 AIFORE 模糊测试解决方案，通过对输入格式的逆向，结合神经网络模型学习，推断程序输入格式。
- [Remote Code Execution from SSTI in the Sandbox: Automatically Detecting and Exploiting Template Escape Bugs, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/zhao-yudi) -  *复旦大学*  Yudi Zhao，PHP 模板引擎模糊测试工具，[TEFuzz 已开源](https://github.com/seclab-fudan/TEFuzz)。
- [MTSan: A Feasible and Practical Memory Sanitizer for Fuzzing COTS Binaries, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/chen-xingman) -  *清华大学*  Xingman Chen，张超团队，提出了一种硬件辅助内存消杀器 MTSan，用于二进制模糊测试，并在 AArch64 上实现了 MTSan 原型。
- [MorFuzz: Fuzzing Processor via Runtime Instruction Morphing enhanced Synchronizable Co-simulation, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/xu-jinyan) -  *浙江大学*  Jinyan Xu，提出了一种针对处理器（RISC-V）的模糊测试工具 [MorFuzz](https://github.com/sycuricon/MorFuzz)，工具已开源。
- [MINER: A Hybrid Data-Driven Approach for REST API Fuzzing, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/lyu) -  *浙江大学*  Chenyang Lyu，一种新的混合数据驱动解决方案，利用神经网络模型预测关键请求参数，提高序列模板中请求的生成质量，[MINER](https://github.com/puppet-meteor/MINER) 工具原型已开源。
- [KextFuzz: Fuzzing macOS Kernel EXTensions on Apple Silicon via Exploiting Mitigations, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/yin) -  *清华大学*  Tingting Yin，张超团队，提出了第一个智能模糊解决方案 KextFuzz，用于检测运行在 Apple Silicon 上的最新 macOS 驱动漏洞。[KextFuzz](https://github.com/vul337/KextFuzz) 未开源。
- [Intender: Fuzzing Intent-Based Networking with Intent-State Transition Guidance, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/kim-jiwon) -  *普渡大学*  Jiwon Kim，这是第一个 IBN 语义感知模糊测试框架。Intender 利用网络拓扑信息和意图操作依赖性 (IOD) 来有效生成测试输入。
- [DDRace: Finding Concurrency UAF Vulnerabilities in Linux Drivers with Directed Fuzzing, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/yuan-ming) -  *清华大学*  Ming Yuan，张超团队，提出了第一个并发定向灰盒模糊测试解决方案 DDRACE，可有效地在 Linux 驱动程序中发现并发 UAF 漏洞。[DDRace](https://github.com/vul337/DDRace) 未开源。
- [CarpetFuzz: Automatic Program Option Constraint Extraction from Documentation for Fuzzing, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/wang-dawei) -  *中国科学院信息工程研究所*  Dawei Wang，利用自然语言处理（NLP）自动从程序文档中提取选项描述并分析关系（例如，冲突、在过滤掉无效组合并只留下有效组合进行模糊测试之前，请先检查选项之间的依赖关系），实现了一个名为 CarpetFuzz 的工具并评估了其性能。[CarpetFuzz](https://github.com/waugustus/CarpetFuzz) 已开源。
- [BoKASAN: Binary-only Kernel Address Sanitizer for Effective Kernel Fuzzing, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/cho) -  *延世大学*  Mingi Cho，开发的一种无需源码编译的黑盒二进制 Kernel Address Sanitizer (KASAN)。
- [Bleem: Packet Sequence Oriented Fuzzing for Protocol Implementations, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/luo-zhengxiong) - *清华大学* Zhengxiong Luo，提出了 Bleem，一种面向数据包序列的用于协议实现漏洞检测的黑盒模糊器。Bleem 不关注单个数据包的生成，而是在序列级别生成数据包，解决协议模糊测试中无状态反馈的问题。
- [autofz: Automated Fuzzer Composition at Runtime, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/fu-yu-fu) - *佐治亚理工学院* Yu-Fu Fu，出了一种自动化的非侵入式元模糊器，称为 autofz，通过动态组合最大限度地发挥现有最先进模糊器的优势，即自动选择什么样的模糊器，[autofz](https://github.com/sslab-gatech/autofz) 已开源。

#### 2022

- [MundoFuzz: Hypervisor Fuzzing with Statistical Coverage Testing and Grammar Inference, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/myung) -  针对 Hypervisor 的模糊测试工具 MundoFuzz，来自于韩国*首尔国立大学* 的 Cheolwoo Myung 等人。
- [TheHuzz: Instruction Fuzzing of Processors Using Golden-Reference Models for Finding Software-Exploitable Vulnerabilities, 2022](https://arxiv.org/abs/2201.09941) - 一种基于新颖的基于硬件的**指令集模糊测试**工具，TheHuzz，来自于美国*得克萨斯农工大学* 。
- [Morphuzz: Bending (Input) Space to Fuzz Virtual Devices, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/bulekov) -  MORPHUZZ 是第一种自动引发现代云中现实世界虚拟设备的复杂 I/O 行为的方法，来自于美国*波士顿大学* 。 
- [Fuzzware: Using Precise MMIO Modeling for Effective Firmware Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski) -  使用精准的MMIO建模提高**固件模糊测试**效率，来自于*波鸿鲁尔大学* 。一种针对 **ARM Cortex-M MCU 固件**进行 Fuzz 的工具，使用 Unicore Engine 仿真，MMIO 寄存器作为 Fuzz 入口，已开源 [Fuzzware](https://github.com/fuzzware-fuzzer/fuzzware)。  
- [FuzzOrigin: Detecting UXSS vulnerabilities in Browsers through Origin Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/kim) - 通过 Origin Fuzzing 检测浏览器中的 UXSS 漏洞，来自于*三星*的研究，已开源 [FuzzOrigin](https://github.com/compsec-snu/fuzzorigin)。
- [Drifuzz: Harvesting Bugs in Device Drivers from Golden Seeds, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/shen-zekun) -  一种针对 **WiFi 和以太网**驱动程序的无硬件混合模糊测试工具，来自于*纽约大学*，已开源 [Drifuzz](https://github.com/buszk/drifuzz-concolic)。
- [Fuzzing Hardware Like Software, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/trippel) - 像软件一样对硬件进行模糊测试，来自于*密歇根大学* 的 Timothy Trippel ， 讲述如何将 RTL 设计的硬件转换为软件模型，并利用覆盖率引导的软件模糊器（如 [AFL](https://github.com/google/AFL)）自动生成测试用例以进行硬件验证，已开源 [hw-fuzzing](https://github.com/googleinterns/hw-fuzzing) 。
- [BrakTooth: Causing Havoc on Bluetooth Link Manager via Directed Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/garbelini) - 来自新加坡科技与设计大学的安全研究人员，他们发现了一个新的**蓝牙芯片安全漏洞** “BrakTooth”，这一漏洞影响了包括英特尔、高通和德州仪器在内的11家供应商的13款蓝牙芯片组，PoC已开源[braktooth_esp32_bluetooth_classic_attacks](https://github.com/Matheus-Garbelini/braktooth_esp32_bluetooth_classic_attacks)，此团队曾在两年前也实现了另外一个 BLE Fuzzing 工具，即 SweynTooth。
- [AmpFuzz: Fuzzing for Amplification DDoS Vulnerabilities, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/krupp) - 用于**流量放大攻击**即 DDoS 漏洞的模糊测试，来自于*CISPA 亥姆霍兹信息安全中心*，已开源 [AmpFuzz](https://github.com/cispa/ampfuzz) 。
- [SGXFuzz: Efficiently Synthesizing Nested Structures for SGX Enclave Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/cloosters) - 针对 Intel 的 SGX 的模糊测试方案，来自于*杜伊斯堡-埃森大学* ，已开源 [sgxfuzz](https://github.com/uni-due-syssec/sgxfuzz)。
- [FRAMESHIFTER: Manipulating HTTP/2 Frame Sequences with Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/jabiyev) -  专为 HTTP/2 开发了一种新颖的基于语法的 fuzzer ，并发现 HTTP/2 到 HTTP/1 转换异常的安全隐患，来自于美国*东北大学*，已开源  [frameshifter](https://github.com/bahruzjabiyev/frameshifter) 。
- [FIXREVERTER: A Realistic Bug Injection Methodology for Benchmarking Fuzz Testing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/zhang-zenong) - 比较理论的 Fuzzing 方法改进，较为理论，暂时没有关注细节，来自于*德克萨斯大学达拉斯分校的*Zenong Zhang  。
- [StateFuzz: System Call-Based State-Aware Linux Driver Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/zhao-bodong) -  也是一个 Fuzzing 方法改进，代码覆盖率引导的模糊测试在测试具备复杂状态的程序（比如网络协议程序、内核驱动）时存在局限，即fuzzer缺乏指导来遍历程序状态因此，作者认为对这些程序，需要使用状态敏感的模糊测试 。来自于 *清华大学网络科学与网络空间研究所* ，即将开源 [StateFuzz](https://github.com/vul337/StateFuzz) 。
- [SyzScope: Revealing High-Risk Security Impacts of Fuzzer-Exposed Bugs inLinux kernel, 2022](https://www.usenix.org/system/files/sec22summer_zou.pdf) - [*加利福尼亚大学河滨分校*](https://www.baidu.com/link?url=JVR9rCnFswT1Ft9lScNrOtEb1bYGYD0nzwMxhblwu6kgXGLdQ2hvaqCOFaYe8ejpLkVJliC0cbCVr_wZJUeU5hM7Lt6ujuE--2GD1B3FtBJgFshjSsRNZAZRuZIlQqnsTvns6y6BWL5PLfeL0jWi0d3JUpINvTBZdhT23WL4KSj-WZGMAEqSH4GIsdDJ7P9NDQru9vgB3_LTw6kCge1CVa&wd=&eqid=ae66d9730006e7190000000661eb9bc2)  Xiaochen Zou 等人开发了 SyzScope，用于评估内核 bug 的影响等级。

#### 2021

- [Constraint-guided Directed Greybox Fuzzing, 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/lee-gwangmu)：约束引导的定向灰盒模糊测试（ constraint-guided DGF ）， 满足一系列约束而不仅仅是到达目标点，将约束定义为目标点和数据条件的组合，并按指定顺序驱动种子满足约束，来自于韩国*首尔国立大学* 。
- [UNIFUZZ: A Holistic and Pragmatic Metrics-Driven Platform for Evaluating Fuzzers, 2021](https://www.usenix.org/biblio-6129)：浙江大学提出一个指标驱动的 fuzzer 评估平台， 设计和开发了 UNIFUZZ，这是一个开源和指标驱动的平台，用于以全面和定量的方式评估模糊器。具体而言，UNIFUZZ 迄今为止已经整合了 35 个可用的模糊器、20 个真实世界程序的基准和六类性能指标，没有发现工具开源地址。
- [Nyx: Greybox Hypervisor Fuzzing using Fast Snapshots and Affine Types, 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/schumilo)：德国波鸿鲁尔大学设计并实现了 [RUB-SysSec](https://github.com/RUB-SysSec)/**[Nyx](https://github.com/RUB-SysSec/Nyx)**，用于在云端虚拟机管理程序进行 fuzzing，这是一种高度优化、覆盖引导的虚拟机管理程序模糊器。
- [Breaking Through Binaries: Compiler-quality Instrumentation for Better Binary-only Fuzzing, 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/nagy)： *弗吉尼亚理工大学*   Stefan Nagy  等人研究实现了**编译器级别的纯黑盒二进制** fuzzing 工具，即 ZAFL，一个将编译器 fuzzing 属性移植到二进制的工具。
- [The Use of Likely Invariants as Feedback for Fuzzers, 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/fioraldi)： 法国通信系统工程师学校与研究中心 提出了一种新的反馈机制，通过考虑程序变量和常量之间的关系来**增加代码覆盖率**。在名为 [eurecom-s3](https://github.com/eurecom-s3)/**[invscov](https://github.com/eurecom-s3/invscov)** 的原型中实现了该技术，该原型基于 LLVM 以及 AFL++。

#### 2020

- [Analysis of DTLS Implementations Using Protocol State Fuzzing](https://www.usenix.org/conference/usenixsecurity20/presentation/fiterau-brostean) (2020)：瑞典[*乌普萨拉大学*](https://www.baidu.com/link?url=xRk-x5EtMxr6AhX3qTQWGiC1pbZmfh8mem1x9_o2MuZAhAFm5haijjK1M21ZlPbJGARysEoJZmQxijhoCzPmXOnj135atLDX4m9thgw0MEI2u47O-pk1BH4bTKSYGCdYnbTL6FL18ZDlCKLg8ypFHq&wd=&eqid=8278386e000070bd000000056047391c) 对 DTLS 实现的首次全面分析，提出的 [TLS-Attacker](https://github.com/tls-attacker/TLS-Attacker)  是一个用于分析TLS实现的开源框架。
- [EcoFuzz: Adaptive Energy-Saving Greybox Fuzzing as a Variant of the Adversarial Multi-Armed Bandit](https://www.usenix.org/conference/usenixsecurity20/presentation/yue) (2020)： [EcoFuzz](https://github.com/MoonLight-SteinsGate/EcoFuzz) 是国防科技大学师生开发的基于 AFL 的自适应节能灰盒模糊器。 基于AFL 的基础上，开发了独特的自适应调度算法以及基于概率的搜索策略，根据结果，EcoFuzz 可以减少 AFL 32％的用例，从而达到 AFL 214％的路径覆盖率。
- [FANS: Fuzzing Android Native System Services via Automated Interface Analysis](https://www.usenix.org/conference/usenixsecurity20/presentation/liu) (2020)：清华大学张超团队联合 360  提出了一种基于自动生成的模糊测试解决方案 FANS，以查找 Android 系统原生服务中的漏洞，作者[刘保证](http://netsec.ccert.edu.cn/people/iromise/)开发的 Native Service Fuzz 工具 fans [开源连接](https://github.com/iromise/fans)，能够根据源码自动推测 Native Service 的接口和入参，进行 fuzzing，工具的限制是需要 AOSP 的编译环境。 
- [Fuzzing Error Handling Code using Context-Sensitive Software Fault Injection](https://www.usenix.org/conference/usenixsecurity20/presentation/jiang) (2020)： 清华大学蒋祖明和白佳举提出了一个名为 FIFUZZ 的新模糊测试框架，检测异常处理。FIFUZZ 的核心是上下文相关的软件故障注入（SFI）方法，该方法可以有效地覆盖不同调用上下文中的错误处理代码，以查找隐藏在具有复杂上下文的错误处理代码中的深层错误。
- [FuzzGen: Automatic Fuzzer Generation, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/ispoglou)： Kyriakos Ispoglou 等人提出的对库接口进行分析的工具。 这是一种用于在给定环境中自动合成复杂库的模糊器的工具。[FuzzGen](https://github.com/HexHive/FuzzGen) 利用*整个系统分析*来推断库的接口，并专门为该库合成模糊器。FuzzGen 不需要人工干预，可以应用于各种库。此外，生成的模糊器利用LibFuzzer 来实现更好的代码覆盖率并暴露库深处的错误。 
- [GREYONE: Data Flow Sensitive Fuzzing, 2020](https://www.usenix.org/conference/usenixsecurity20/presentation/gan)：清华大学张超团队提出的另外一个一种数据流敏感的模糊解决方案 GREYONE。思想可观，由于并没有开源，落地比较困难。
- [SweynTooth: Unleashing Mayhem over Bluetooth Low Energy, 2020](https://www.usenix.org/conference/atc20/presentation/garbelini) - 来自新加坡科技与设计大学的安全研究人员，他们使用了 Noridc nRF52840 实现低成本的 **BLE 全栈模糊测试**工具，PoC 已开源  [sweyntooth_bluetooth_low_energy_attacks](https://github.com/Matheus-Garbelini/sweyntooth_bluetooth_low_energy_attacks)。

#### 2019 ⤵ 

- [Fuzzification: Anti-Fuzzing Techniques, 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/jung)： *佐治亚理工学院* 学者提出的一个对抗 fuzzing 的手段，主要是防止安全人员对自己的产品进行 fuzzing，这个视角比较新颖，值得一看。
- [AntiFuzz: Impeding Fuzzing Audits of Binary Executables, 2019](https://www.usenix.org/conference/usenixsecurity19/presentation/guler)：同样是一个对抗 fuzzing 的方案，只不过引入了 不同的技术保护二进制可执行文件，防止被 fuzzing。
- [MoonShine: Optimizing OS Fuzzer Seed Selection with Trace Distillation, 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/pailoor)：哥伦比亚大学团队开发的 [MoonShine](https://github.com/shankarapailoor/moonshine)，这是一种新颖的策略，可从真实程序的系统调用中提取 fuzz 种子。作为对 Syzkaller 的扩展， MoonShin 能够将 Syzkaller 的 Linux 内核代码覆盖率平均提高 13％。
- [QSYM : A Practical Concolic Execution Engine Tailored for Hybrid Fuzzing, 2018](https://www.usenix.org/conference/usenixsecurity18/presentation/yun)：*佐治亚理工学院* 学者设计了一种快速的，称为 [QSYM](https://github.com/sslab-gatech/qsym) 的 Conolic 执行引擎，支持混合 fuzzing。
- [OSS-Fuzz - Google's continuous fuzzing service for open source software, 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/serebryany)：谷歌的 OSS-Fuzz 框架，没什么好说的，主要是帮助开发人员在开发阶段引入的框架，继承多个 fuzz 工具。
- [kAFL: Hardware-Assisted Feedback Fuzzing for OS Kernels, 2017](https://www.usenix.org/conference/usenixsecurity17/technical-sessions/presentation/schumilo)：对于内核的 fuzzing，崩溃往往会导致系统重启，内核中的任意一个错误都可能带来深远影响。  *波鸿鲁尔大学的*谢尔盖·舒米舒等人提出的独立于*操作系统*和*硬件辅助的方式*解决了覆盖指导的内核模糊问题：利用虚拟机管理程序和英特尔的 *Processor Trace*（PT）技术。 

### IEEE S&P

#### 2024

- [AFGen: Whole-Function Fuzzing for Applications and Libraries, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a011/1RjE9PjiDss) - AFGen（全函数模糊测试应用和库）是一种用于应用程序和库的全函数模糊测试工具。它是一种基于符号执行的模糊测试技术，通过符号执行进行静态分析，[代码即将开源](https://github.com/Marsman1996/AFGen)，作者来自于中国科学院大学的[刘雨薇](https://www.computer.org/csdl/search/default?type=author&givenName=Yuwei&surname=Liu)。
- [Chronos: Finding Timeout Bugs in Practical Distributed Systems by Deep-Priority Fuzzing with Transient Delay, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a109/1Ub23heRtUA) - Chronos的目标是提供一个实用的工具，帮助开发者发现并解决分布式系统中的超时错误。通过深度优先模糊测试和瞬时延迟模拟，与上面一篇论文一样，感觉较为学术化，作者来自清华大学的[Yuanliang Chen](https://www.computer.org/csdl/search/default?type=author&givenName=Yuanliang&surname=Chen)。
- [DY Fuzzing: Formal Dolev-Yao Models Meet Cryptographic Protocol Fuzz Testing, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a096/1Ub234bjuWA) - 一个针对密码学算法库进行模糊测试的模型，如针对 OpenSSL/wolfSSL，作者为独立研究员[Max Ammann](https://www.computer.org/csdl/search/default?type=author&givenName=Max&surname=Ammann)，已经有基于 DY 模型实现了 **TLS Fuzz** 的工具，[tlspuffin](https://github.com/tlspuffin/tlspuffin)。
- [LABRADOR: Response Guided Directed Fuzzing for Black-box IoT Devices, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a127/1Ub23HQTJ1C) - 又是一个针对固件黑盒 Fuzz 的工具，来自于信息工程大学的[Hangtian Liu](https://www.computer.org/csdl/search/default?type=author&givenName=Hangtian&surname=Liu)，也是张超团队的工作。相比 SNIPUZZ、BOOFUZZ 和 FIRM-AFL 能够发现更多的漏洞，同时是 SaTC 发现的漏洞的 8.57 倍。与以前工作不同的是，**LABRADOR 似乎不需要进行固件仿真**，而是在真机上进行 Fuzz 测试，通过网络响应来推断固件的执行跟踪，并推导出测试的代码覆盖率，未见开源。
- [Predecessor-aware Directed Greybox Fuzzing, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a040/1RjEaeMELbq) - 属于定向模糊测试的范畴，提出了一种 Predecessor-aware Directed Greybox Fuzzing (PDGF) 方法，并将 DGF 视为一种路径搜索问题，是一种结合了先前路径感知的灰盒模糊测试技术，较为学术。
- [SATURN: Host-Gadget Synergistic USB Driver Fuzzing, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a051/1RjEaqzRsfC) - 针对 USB 协议的 Fuzz 工具，来自清华大学[Yiru Xu](https://www.computer.org/csdl/search/default?type=author&givenName=Yiru&surname=Xu)。工具已开源：[Saturn](https://github.com/THU-WingTecher/Saturn)。
- [SoK: Prudent Evaluation Practices for Fuzzing, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a137/1Ub23V26Svm) - 一篇来自*德国CISPA亥姆霍兹信息安全中心*的有趣论文。在 2018~2023 年安全顶会公开发表的 289 篇有关 Fuzzing 的论文中，74% 的论文公开了源码，60% 的论文工程代码受到了评估，**各项 Fuzzing 研究论文发现的 CVE 的数量和质量存疑**，并表达观点，CVE 不是主要影响 Fuzzer 质量的标准。作者对其中的 8 篇进行深入评估，**并对这些论文的研究结果提出质疑**。让人遗憾的是，这 8 篇数据有问题的论文均来自国内。包括 *深圳大学、中国科学院大学、上海交大、奇安信&天津大学，国防科大、华盛顿州立大学（留学生）、中科学信工所、中国科学院大学国家计算机网络入侵防护中心*。
- [SyzTrust: State-aware Fuzzing on Trusted OS Designed for IoT Devices, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a070/1RjEaG9OpTa) - 针对 TEE 设计的模糊测试工具，基于 Syzkaller，在开发板上测试，因此 TEE 需要能够运行在开发板环境上，作者来自浙江大学，工具已开源，[SyzTrust](https://github.com/SyzTrust/syztrust)。
- [Titan: Efficient Multi-target Directed Greybox Fuzzing, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a059/1RjEaxqvmQ8) - 一篇较为学术的研究定向模糊测试的沦陷，来自香港科技大学。
- [To Boldly Go Where No Fuzzer Has Gone Before: Finding Bugs in Linux' Wireless Stacks through VirtIO Devices, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a024/1RjEa0y9RMQ) - 一种基于 VirtIO 设备驱动程序的新型模糊测试工具 [VirtFuzz](https://github.com/cyruscyliu/virtfuzz-evaluation)，从真实设备收集数据，在虚拟环境进行 Fuzz，德国达姆施塔特工业大学安全移动网络实验室（SEEMOO）[Sönke Huster](https://www.computer.org/csdl/search/default?type=author&givenName=Sönke&surname=Huster)。

#### 2023

- [DEVFUZZ: Automatic Device Model-Guided Device Driver Fuzzing, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Nrc0AgBCgM/pdf) - 针对驱动的模糊测试，文章指出 [DEVFUZZ](https://github.com/lzto/afl-proxy.git)(已开源) 针对 PCI、USB、RadpiIO、I2C 总线，且不需要实际设备，通过符号执行模拟硬件设备，文章来源 [纽约州立大学石溪分校](http://www.baidu.com/link?url=CNFrDbfV-OGIsAIhXj42MU2R4vvrYFYJs-YoF5tOj1hpIrk9bHzvCM_KeFSpAtV4oGV69Yf3gnwfyEk_FURhr1QOoL9__9c2EqaKnaJdSFXvWa7SJ1Qn___SfZhMFX2oa3yr0jPlOAnHsOqUuyYxEEXiGFIobGIbUTM2fM3JFLSZ9faRv8nRNultM2fefeqTAoWfkzTQ8F09Yp3WdacPYa)。这似乎与 **ARM-M 固件仿真**有关，且使用了 S2E，感兴趣的同学可以阅读华科周威老师 2021 年在 Usenix 上发表的论文 Fuzzware，后续“固件章节有收录”。
- [ODDFUZZ: Discovering Java Deserialization Vulnerabilities via Structure-Aware Directed Greybox Fuzzing, 2023](https://arxiv.org/abs/2304.04233) - 一种针对 Java 反序列化漏洞的新颖混合解决方案 ODDFUZZ，尚未开源，来自于扬州大学曹思聪。
- [Finding Specification Blind Spots via Fuzz Testing, 2023](https://cs.uwaterloo.ca/~m285xu/assets/publication/fast-paper.pdf) - 形式化验证与 Fuzz 测试，一篇学术型论文，来自[加拿大滑铁卢大学徐萌研究组](http://mp.weixin.qq.com/s?__biz=Mzg5ODUxMzg0Ng==&mid=2247486356&idx=1&sn=93f9480433a00b58b39a088a5f1962d1&chksm=c060254df717ac5b8faf31069f41b4fc08ba4769ce9327ae5946822cc5db94f481db7d1c8179&scene=21#wechat_redirect)的博士生纪儒，非我擅长的领域，感兴趣可以阅读一下。
- [RSFuzzer: Discovering Deep SMI Handler Vulnerabilities in UEFI Firmware with Hybrid Fuzzing, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Js0Ek1SE6c/pdf) - 一种针对 UEFI 固件混合灰盒模糊测试技术。RSFUZZER 能够学习输入接口和格式信息，并探测由调用多个 SMI 处理程序触发的深层隐藏漏洞。来自中国科学院信息工程研究所霍玮研究组，未发现开源。
- [SegFuzz: Segmentizing Thread Interleaving to Discover Kernel Concurrency Bugs through Fuzzing, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1NrbZrWlldK/pdf) - 一个用于内核并发漏洞的模糊测试框架[SegFuzz](https://github.com/casys-kaist/segfuzz.git)(已开源)。众所周知，条件竞争类的漏洞很难通过传统 Fuzz 实现 ，但是使用方法似乎没有详细介绍，文章来自韩国科学技术院 Dae R. Jeong。
- [SelectFuzz: Efficient Directed Fuzzing with Selective Path Exploration, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Js0DBwgpwY/pdf) - 文章主要描述如何提升定向模糊测试（DGF）的效率和准确性，从而提升检测软件漏洞的有效性。[SelectFuzz](https://github.com/cuhk-seclab/SelectFuzz)(已开源) 通过选择性路径探索来提高 DGF 的有效性，从代码上看，工具原型也是基于 AFL，文章来自香港大学 [Changhua Luo](https://www.computer.org/csdl/search/default?type=author&givenName=Changhua&surname=Luo)。
- [TEEzz: Fuzzing Trusted Applications on COTS Android Devices, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1He7XWu6nJe/pdf) - **针对 TEE 的 Fuzzing 工具**，如何在不知道设备运行的操作系统的情况下，直接分析raw memory dump 来获取更多运行时信息，作者使用真实设备，而非仿真，适配了三种流行的 TEE 实现：Qualcomm 安全执行环境 (QSEE) ，用于包括流行的 Nexus 和 Pixel 系列；TrustedCore (TC) ，用于华为设备；开放式可移植可信执行环境 (OPTEE) ，这是基于 TZ 的 TEE 的实际参考实现，来自于洛桑联邦理工学院 [Marcel Busch](https://www.computer.org/csdl/search/default?type=author&givenName=Marcel&surname=Busch)。
- [UTOPIA: Automatic Generation of Fuzz Driver using Unit Tests, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1He7YBzoF0c/pdf) - 来自于三星工程师的 [UTOPIA](https://github.com/Samsung/UTopia.git)，一种开源工具和分析算法，可以从现有的单元测试中自动合成有效的模糊测试驱动程序。
- [VIDEZZO: Dependency-aware Virtual Device Fuzzing, 2023](https://www.computer.org/csdl/pds/api/csdl/proceedings/download-article/1Nrc0ztdpDy/pdf) - 文章来自于浙江大学的[刘强](https://www.computer.org/csdl/search/default?type=author&givenName=Qiang&surname=Liu)，针对**虚拟机的模糊测试**，目前，[ViDeZZo](https://github.com/HexHive/ViDeZZo)(已开源) 支持 QEMU（6.1.50 及更高版本）和 VirtualBox (C++)，涵盖音频、存储、网络、USB 和图形虚拟设备，并涵盖 i386、x86_64、ARM 和 AArch64 版本。
- [Toss a Fault to Your Witcher: Applying Grey-box Coverage-Guided Mutational Fuzzing to Detect SQL and Command Injection Vulnerabilities, 2023](https://www.computer.org/csdl/proceedings-article/sp/2023/933600a116/1He7XPiaynS) - 首个使用 AFL Fuzz Web 应用程序的工具，它利用突变模糊测试来探索 Web 应用程序和故障升级来检测命令和 SQL 注入漏洞。[Witcher](https://github.com/sefcom/Witcher) 已开源。

#### 2022

- [JIGSAW: Efficient and Scalable Path Constraints Fuzzing, 2022](https://www.cs.ucr.edu/~heng/pubs/jigsaw_sp22.pdf) -  将路径约束编译为本地函数，提高分支翻转率的 fuzzer，来自于美国加州大学 Ju Chen，工具已开源 [JIGSAW](https://github.com/R-Fuzz/jigsaw)。
- [PATA: Fuzzing with Path Aware Taint Analysis, 2022](http://www.wingtecher.com/themes/WingTecherResearch/assets/papers/sp22.pdf) -  清华大学软件学院软件系统安全保障小组， 这篇论文主要讨论了在 fuzzing 中**路径感知的污点分析技术**（path-aware taint analysis）的应用。
- [FuzzUSB: Hybrid Stateful Fuzzing of USB Gadget Stacks, 2022](https://ieeexplore.ieee.org/document/9833593) -  混合fuzzing技术在USB上的应用，来自于美国普林斯顿大学的 [Kyungtae Kim](https://ieeexplore.ieee.org/author/37087006508) 。
- [Effective Seed Scheduling for Fuzzing with Graph Centrality Analysis, 2022](https://arxiv.org/abs/2203.12064) - 美国哥伦比亚大学，Dongdong She 等人使用图论中心性分析进行模糊测试的有效种子调度，此方案被称为 [K-Scheduler](https://github.com/Dongdongshe/K-Scheduler)，已开源。
- [BEACON: Directed Grey-Box Fuzzing with Provable Path Pruning, 2022](https://qingkaishi.github.io/public_pdfs/SP22.pdf) - 香港科技大学 Heqing Huang 等人实现的一种称之为 BEACON 的**定向模糊测试**。这是基于 LLVM 灰盒 Fuzzer，需要将输入源代码编译为 LLVM 位代码，进行静态分析。分析后插桩，LLVM 位代码被编译为可执行二进制文件，可以与各种模糊引擎集成。未见开源。

#### 2021

- [DiFuzzRTL: Differential Fuzz Testing to Find CPU Bugs, 2021](https://ieeexplore.ieee.org/document/9519470)：韩国首尔大学，[DifuzzRTL](https://github.com/compsec-snu/difuzz-rtl)，一种专门发现 CPU RTL 漏洞的 fuzz 工具，已开源。
- [StochFuzz: Sound and Cost-effective Fuzzing of Stripped Binaries by Incremental and Stochastic Rewriting, 2021](https://ieeexplore.ieee.org/document/9519407)： 普渡大学及中国人民大学的华人团队开发了一种新的 fuzz 技术，被称为  incremental and stochastic rewriting ，优于 afl-unicorn，利用更低的开销，提高了**黑盒二进制 fuzzing** 的效率，相关工具已开源：[ZhangZhuoSJTU](https://github.com/ZhangZhuoSJTU)/**[StochFuzz](https://github.com/ZhangZhuoSJTU/StochFuzz)**。
- [NtFuzz: Enabling Type-Aware Kernel Fuzzing on Windows with Static Binary Analysis, 2021](https://ieeexplore.ieee.org/document/9519448)： 韩国科学技术院 (KAIST)  Jaeseung Cho 等人提出的一个静态二进制分析器，可以自动推断出 Windows 系统调用，该分析器被整合到 [SoftSec-KAIST](https://github.com/SoftSec-KAIST)/**[NTFuzz](https://github.com/SoftSec-KAIST/NTFuzz)**，一个 **Windows 系统调用** fuzzing 框架，首次将静态二进制分析技术与 Windows 内核的 fuzzing 技术相结合。
- [Diane: Identifying Fuzzing Triggers in Apps to Generate Under-constrained Inputs for IoT Devices, 2021](https://ieeexplore.ieee.org/document/9519432)： 加州大学圣巴巴拉分校 Nilo Redini 等人通过使用网络流量和控制目标物联网设备的应用程序的混合分析来解决输入生成问题 ，工具名为 [ucsb-seclab](https://github.com/ucsb-seclab)/**[diane](https://github.com/ucsb-seclab/diane)**，已开源， 与 IoTFuzzer 较为相似，弥补了 IoTFuzzer 的一些缺点。
- [One Engine to Fuzz 'em All: Generic Language Processor Testing with Semantic Validation, 2021](https://ieeexplore.ieee.org/document/9519403)： 佐治亚理工学院 Yongheng Chen 等人提出了一个通用 fuzzing 框架（[s3team](https://github.com/s3team)/**[Polyglot](https://github.com/s3team/Polyglot)** ），目的是为了探索不同编程语言的处理器而生成高质量的模糊测试用例，实现各个语言之间的通用性和适用性。 相比于当前最先进的通用型 fuzz：包括基于变异的 fuzzer **AFL** 以及混合型 fuzzer **QSYM** 和基于语法的 fuzzer **Nautilus** 能够更有效地生成高质量的测试用例。

#### 2020

- [IJON: Exploring Deep State Spaces via Fuzzing, 2020](https://www.syssec.ruhr-uni-bochum.de/media/emma/veroeffentlichungen/2020/02/27/IJON-Oakland20.pdf)： 通过改造 AFL 探测程序的空间状态，发现更多程序行为，并拿游戏"超级玛丽"来作演示。 作者对超级玛丽作了修改，使所有的键盘命令都可以从标准输入中读取，并且马里奥只能不停地向右跑，只要停下来就死掉，这个设计主要是为节省时间。 
- [Krace: Data Race Fuzzing for Kernel File Systems, 2020](https://www.cc.gatech.edu/~mxu80/pubs/xu:krace.pdf)：介绍了 KRACE，一个端到端的模糊框架，它将并发方面引入基于覆盖引导的文件系统 fuzzing 中。
- [Pangolin:Incremental Hybrid Fuzzing with Polyhedral Path Abstraction, 2020](https://qingkaishi.github.io/public_pdfs/SP2020.pdf)： 香港科技大学，混合 fuzing 结合了符号执行与模糊测试的优点，已经逐渐成为基于覆盖引导的 fuzzing 技术的重要发展方向之一。尽管在实现高覆盖率方面取得了巨大进展，但众所周知，混合模糊仍然存在效率问题。  将约束求解后对信息重用起来，是有可能实现 Constrained Mutation 和 Guided Constraint Solving，从而**提升混合 fuzz 效率**。 
- [RetroWrite: Statically Instrumenting COTS Binaries for Fuzzing and Sanitization, 2020](https://www.semanticscholar.org/paper/RetroWrite%3A-Statically-Instrumenting-COTS-Binaries-Dinesh-Burow/845cafb153b0e4b9943c6d9b6a7e42c14845a0d6)：该团队开发了一种**二进制重写工具 retrowrite** 用于支持 AFL 和 ASAN，并证明它可以在保持精度的同时达到编译器级的性能。使用 retrowriter 重写用于覆盖引导的二进制文件在性能上与编译器检测的二进制文件相同，性能比基于 defaultQEMU 的检测高出 4.5 倍。该工具已开源：https://github.com/HexHive/retrowrite/，同时限制非常多，比如目标二进制只能是 x86_64 架构，必须包含符号表等。

#### 2019 ⤵ 

- [Full-speed Fuzzing: Reducing Fuzzing Overhead through Coverage-guided Tracing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000b122/19skgbGVFEQ)：  弗吉尼亚理工大学 ，创建了一个基于静态二进制工具或 Dyninst 的实现，称为 [UnTracer](https://github.com/FoRTE-Research/UnTracer-AFL) ，该工具能够**降低 fuzzing 开销**，从而提高速度。
- [Fuzzing File Systems via Two-Dimensional Input Space Exploration, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a594/19skfLYOpaw)： 本文的作者佐治亚理工学院的许文及作者所在的研究组，长期从事二进制相关研究。 本工作实现了一个基于反馈进化的 fuzzer——[JANUS](https://github.com/sslab-gatech/janus)，**通用文件系统 fuzzer**，可以高效的探索文件系统的两个维度的输入空间。
- [NEUZZ: Efficient Fuzzing with Neural Program Smoothing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a900/19skg5XghG0)： 哥伦比亚大学落地项目，**利用神经网络来模拟程序的分支行为**。 [neuzz](https://github.com/Dongdongshe/neuzz) 通过有策略地修改现有 seeds 的一些 bytes 以期来产生 interesting seeds 从而能触发未执行过的 edge。而这个策略要借助神经网络才能得以具体实施。
- [Razzer: Finding Kernel Race Bugs through Fuzzing, 2019](https://www.computer.org/csdl/proceedings-article/sp/2019/666000a296/19skfwZLirm)：韩国科学技术院 (KAIST) DR Jeong  设计并提出了**针对内核中的数据竞争类型漏洞的模糊测试（fuzzing）工具 Razzer** 。 [Razzer](https://github.com/compsec-snu/razzer) 的两阶段模糊测试基于Syzkaller。确定性调度程序是使用 QEMU / KVM 实现的。
- [Angora: Efficient Fuzzing by Principled Search, 2018](http://web.cs.ucdavis.edu/~hchen/paper/chen2018angora.pdf)：上海交通大学 peng chen 等人开发的 [Angora](https://github.com/AngoraFuzzer/Angora)，主要目标是**提高分支覆盖率，不使用符号执行的方法来解决路径约束** 。 该工具目前活跃度较高，一直处于稳定更新中。
- [CollAFL: Path Sensitive Fuzzing, 2018](http://chao.100871.net/papers/oakland18.pdf)：清华大学张超团队对AFL中的 coverage inaccuracy 和 seed **选择策略做了改进**，改进后的工具称为 [CollAFL](https://github.com/batgui/collafl)。
- [T-Fuzz: fuzzing by program transformation, 2018](https://nebelwelt.net/publications/files/18Oakland.pdf)： Purdue University 的 Peng Hui 等人研发的 [T-fuzz](https://github.com/HexHive/T-Fuzz) 通过**去掉 santiy check 来提高覆盖率**。T-fuzz 利用覆盖率来引导产生输入。当不能访问到新的路径时，T-fuzz会去掉 check，以保证 fuzz 能继续进行，发现新的路径和 bug。 
- [Skyfire: Data-Driven Seed Generation for Fuzzing, 2017](https://www.ieee-security.org/TC/SP2017/papers/42.pdf)： 针对**处理高度结构化输入**的程序(比如解析XML的引擎程序)，本文提出了一种**种子生成方法**，通过大量样本训练**带概率的上下文有关文法**，通过训练好的文法，自动生成符合程序输入要求的种子，用于后续的Fuzz。 

### ACM CCS

#### 2023

- [DSFuzz: Detecting Deep State Bugs with Dependent State Exploration, 2023](https://dl.acm.org/doi/10.1145/3576915.3616594):  基于深度学习研究状态机与代码路径的关系，简言之就是一个针对状态机建模，以提高代码覆盖率，接近千禧年出生的华人[Yinxi Liu]([Yinxi Liu](https://yinxi.site/))。
- [Fuzz on the Beach: Fuzzing Solana Smart Contracts, 2023](https://arxiv.org/abs/2309.03006):  Solana 是一种构建数字货币，如分布式工具的平台，而本文就是对这个平台诞生的智能合约的 Fuzz，来自德国的杜伊斯堡-埃森大学。
- [Greybox Fuzzing of Distributed Systems, 2023](https://mengrj.github.io/files/CCS23.pdf):  针对分布式系统（如 Redis）的灰盒 Fuzz 工具，[已开源](https://github.com/dsfuzz/mallory)，环境使用 Docker，可以自己构建，Jepsen + Mallory，新加坡国立大学 Ruijie Meng。
- [HOPPER: Interpretative Fuzzing for Libraries, 2023](https://dl.acm.org/doi/10.1145/3576915.3616610):  一项比较有意思的研究，一种新的 API Fuzz 工具，不需要像开发那样对 API 的用法了如指掌，而只需要知道 Hopper 如何使用。目前的局限性是只针对 C 而非 C++ 语言编写的库，[Hopper 开源地址](https://github.com/FuzzAnything/Hopper)，[腾讯安全大数据实验室](http://www.baidu.com/link?url=aWqSg8WuLS7zTXIhjBtwYRtDkRYa9FBRmZWPvPgPJ6x5cZJO7SHTqM_YAqot7DF1LdMA6fwn0IJGpbWxnGHsfglRNqwnqNY5tH1I_LyyH0Gt78Po_-Jbb0O2e0dXJH7pyLfzX4YfzOgNJNNEcFS6AbdYK4AP_wRnMMHAXgZiv9zHGFa84udhi8xZfIY5pvkJnOP3Wi7-uzNkugatATRZ6K)。
- [Profile-guided System Optimizations for Accelerated Greybox Fuzzing, 2023](https://dl.acm.org/doi/10.1145/3576915.3616636):  优化 AFL 的持久模式和 Fork 系统调用，提升 Fuzz 效率，美国犹他大学，改进后的 [AFL/AFL++ 分支代码](AFL/AFL++ 分支代码)。
- [NestFuzz: Enhancing Fuzzing with Comprehensive Understanding of Input Processing Logic, 2023](https://dl.acm.org/doi/10.1145/3576915.3623103):  复旦大学系统软件与安全实验室研究成果，专门针对开源工具进行 Fuzz 的工具 [NestFuzz](https://github.com/fdu-sec/NestFuzz)，仍然是基于 AFL 改进的工具，提出了一种新颖的数据结构，即输入处理树，它可以表示输入格式的整体结构。在模糊测试的第二阶段，NestFuzz 设计了一种级联依赖性感知突变策略。基于已识别的依赖关系，每当 NestFuzz 改变（字段或结构级别）输入时，它都会级联改变其他受影响的字段或子结构以维持结构有效性。
- [SyzDirect: Directed Greybox Fuzzing for Linux Kernel, 2023](https://dl.acm.org/doi/10.1145/3576915.3623146):  仍然是来自于复旦大学系统软件与安全实验室，好在他们的工具都已开源：[SyzDirect](https://github.com/seclab-fudan/SyzDirect)，基于 Syzkaller 的改进。
- [PyRTFuzz: Detecting Bugs in Python Runtimes via Two-Level Collaborative Fuzzing, 2023](https://dl.acm.org/doi/10.1145/3576915.3623166):  顾名思义，就是一个用于检测 Python 运行时中的错误的模糊测试工具。它采用了两级模糊的方法，即单元测试级别的模糊和运行时级别的模糊，[PyRTFuzz 已开源](https://github.com/awen-li/PyRTFuzz)，[作者简介](https://awen-li.github.io/)。
- [Poster: Combining Fuzzing with Concolic Execution for IoT Firmware Testing, 2023](https://dl.acm.org/doi/10.1145/3576915.3624373)：又是一个针对 **IoT 固件的 Fuzz** 工具。在以前固件模糊测试的基础上结合了符号执行。但是其限制仍然是目标固件要支持全系统仿真。因此，本篇论文仍然没有解决固件 Fuzz 测试的核心问题，即仿真，作者来自于韩国世宗大学。

#### 2022 ⤵ 

- [SFuzz: Slice-based Fuzzing for Real-Time Operating Systems, 2022](https://dl.acm.org/doi/10.1145/3548606.3559367):  基于切片的新型模糊器 SFuzz，用于检测 RTOS 中的安全漏洞，来自上海交通大学。
- [LibAFL: A Framework to Build Modular and Reusable Fuzzers, 2022](https://dl.acm.org/doi/10.1145/3548606.3560602):   **LibAFL**，这是一个构建模块化和可重用模糊器的框架，来自于谷歌的个人研究者，已开源 **[LibAFL](https://github.com/AFLplusplus/LibAFL)**。
- [JIT-Picking: Differential Fuzzing of JavaScript Engines, 2022](https://dl.acm.org/doi/10.1145/3548606.3560624): JavaScript 引擎的模糊测试，来自德国 *波鸿鲁尔大学*。
- [MC2: Rigorous and Efficient Directed Greybox Fuzzing, 2022](https://dl.acm.org/doi/10.1145/3548606.3560648): 复杂性理论框架，将定向灰盒模糊测试作为一个 oracle 引导的搜索问题，一个较为学术型的 Fuzz 改进，来自美国纽约哥伦比亚大学。
- [Favocado: Fuzzing the Binding Code of JavaScript Engines Using Semantically Correct Test Cases, 2021](https://www.ndss-symposium.org/ndss-paper/favocado-fuzzing-the-binding-code-of-javascript-engines-using-semantically-correct-test-cases/)：美国亚利桑那州立大学师生提出一种对 **JS 引擎**中绑定层代码进行 fuzzing 的工具：[Favocado](https://github.com/favocado/Favocado)。作者在对在4个不同的JavaScript运行时系统fuzz时，发现了61个新的bug，其中33个是安全漏洞，13个已经被CVE收录。
- [WINNIE : Fuzzing Windows Applications with Harness Synthesis and Fast Cloning, 2021](https://www.ndss-symposium.org/ndss-paper/winnie-fuzzing-windows-applications-with-harness-synthesis-and-fast-cloning/)： 利用合成和快速克隆对 **Windows 应用程序**进行模糊测试 ， *佐治亚理工学院* 的作者构建了一个端到端 [WINNIE](https://github.com/sslab-gatech/winnie) 系统，包含两个组件：可从二进制文件中自动合成工具的生成器，以及一个高效的 Windows forkserver。 对比工具： WinAFL 。
- [PGFUZZ: Policy-Guided Fuzzing for Robotic Vehicles, 2021](https://www.ndss-symposium.org/ndss-paper/pgfuzz-policy-guided-fuzzing-for-robotic-vehicles/)：普度大学 *Hyungsub Kim* 等人设计的一个针对机器车辆（ Robotic vehicles, RVs）fuzzing 工具，即 [PGFUZZ](https://github.com/purseclab/PGFUZZ)，应用场景较为有限。
- [Reinforcement Learning-based Hierarchical Seed Scheduling for Greybox Fuzzing, 2021](https://www.ndss-symposium.org/ndss-paper/reinforcement-learning-based-hierarchical-seed-scheduling-for-greybox-fuzzing/)： *加州大学河滨分校* 华人团队通过引入多级覆盖和设计了基于强化学习的分层调度器，保留更多有价值的种子。即更加细粒度衡量代码覆盖率和更加合理的种子调度策略。
- [DIFUZE: Interface Aware Fuzzing for Kernel Drivers, 2017](https://acmccs.github.io/papers/p2123-corinaA.pdf) ： 圣塔芭芭拉大学的 Jake Corina 等提出的一个 seed 生成方案。通过**优化种子生成**，同样也可以达到提高 fuzzing 效率的效果。经过验证，[DIFUZE](https://github.com/ucsb-seclab/difuze) 相较于现有的 fuzzer 在 ioctl() 接口上，确实存在着明显的优势。这也是显然的，DIFUZE 相较于其他的工具在 fuzzing这样一个需要超大信息量的接口上提供了足够的信息，支撑它挖掘出大于其他工具几个数量级的信息量。
- [Learning to Fuzz from Symbolic Execution with Application to Smart Contracts, 2019](https://files.sri.inf.ethz.ch/website/papers/ccs19-ilf.pdf)：苏黎世联邦理工学院 Jingxuan He 等人提出了一种从符号执行中学习 fuzzer 的新方法，将其应用于智能合约中。
- [Matryoshka: fuzzing deeply nested branches, 2019](https://web.cs.ucdavis.edu/~hchen/paper/chen2019matryoshka.pdf)： 字节跳动人工智能实验室，灰盒fuzz近年来取得了令人瞩目的进展，从基于启发式的随机变异进化到求解单个分支约束。但是，它们很难解决包含深度嵌套条件语句的路径约束。作者开发了一个工具 Matryoshka1 实现深层次嵌套路径的覆盖。
- [Hawkeye: Towards a Desired Directed Grey-box Fuzzer, 2018](https://chenbihuan.github.io/paper/ccs18-chen-hawkeye.pdf)：新加坡南洋理工大学，Hawkeye 是一个定向模糊测试技术，本文提出 4 个定向型 fuzzer 的特性并进行改进：考虑所有到达目标点的路径，不管长短；平衡静态分析的开销和实用性；合理分配能量；适应性变异策略。
- [IMF: Inferred Model-based Fuzzer, 2017](http://daramg.gift/paper/han-ccs2017.pdf)：现有的内核模糊技术涉及将随机输入值输入到内核 API 函数中。然而，这样一个简单方法并没有揭示内核代码深处潜在的 bug，作者提出 IMF 模型，利用API函数调用之间的推断依赖模型来发现内核的深层缺陷。
- [SemFuzz: Semantics-based Automatic Generation of Proof-of-Concept Exploits, 2017](https://www.informatics.indiana.edu/xw7/papers/p2139-you.pdf)： 印第安纳大学伯明顿分校华人研发的 SemFuzz，这是一种利用漏洞相关文本（如 CVE 报告和 Linux git 日志）来指导 PoC 攻击自动生成的新技术。
- [Directed Greybox Fuzzing, 2017](https://dl.acm.org/citation.cfm?id=3134020)： 2017 年 Bohme 提出了 DGF 的概念，并且完成了名为 AFLGo 的工具，即定向模糊测试。
- [SlowFuzz: Automated Domain-Independent Detection of Algorithmic Complexity Vulnerabilities, 2017](https://arxiv.org/pdf/1708.08437.pdf)：主要讲述 fuzzing 中正则表达式带来的问题，并实现了相应的改进算法。
- [DIFUZE: Interface Aware Fuzzing for Kernel Drivers, 2017](https://acmccs.github.io/papers/p2123-corinaA.pdf)： 圣塔芭芭拉大学的 Jake Corina  设计并完成了**针对用户态与内核驱动关键接口 ioctl() 的 fuzzing 工具 DIFUZE**， [DIFUZE](https://github.com/ucsb-seclab/difuze) 首先对内核代码进行静态分析，完成interface 的 recovery，获取 interface 的关键信息，并基于这些有效的信息去生成更加合理的 fuzzing 输入，得到一个更好的 fuzzing 效果。  

## 3 Tools

这里收录常见并且实用的工具，多数工具经过笔者实践，具有一定的普适性。也有一些优秀但是很久没有维护更新，并且适用场景非常有限的工具，未包含在其中。

### 变异器

- [Radamsa](https://gitlab.com/akihe/radamsa) ：Radamsa 是用于健壮性测试的测试用例生成器。通过读取有效数据的样本文件并从中生成令人感兴趣的不同输出来工作。 
- [zzuf](https://github.com/samhocevar/zzuf) ：一个 fuzzer 的输入程序，作为一个优秀的开源项目，已经有不少国外的大型项目引入 zzuf，作为各种畸形数据的生成。

### 二进制

- [afl-unicorn: Fuzzing The 'Unfuzzable' ](https://www.youtube.com/watch?v=OheODvF0884)： [Battelle](https://www.battelle.org/cyber) 在  **ShmooCon 2018** 上发布的一个工具，已经有大佬将演讲视频添加[中文字幕](https://www.bilibili.com/video/av83051615/)并上传到 B 站上。该[工具](https://github.com/Battelle/afl-unicorn) 弥补了 afl 的不足，可以对任意二进制代码片段进行 fuzz，作为一个完全使用**黑盒进行 fuzz** 的工具，afl-unicorn 也保留了 afl 原有的代码覆盖率统计，根据反馈对种子进行变异，从而提高代码覆盖。
- [Intriguer: Field-Level Constraint Solving for Hybrid Fuzzing](https://dl.acm.org/doi/10.1145/3319535.3354249)：韩国延世大学发布在安全顶会 **CCS 2019** 上的一篇关于 fuzzer 性能改进的文章。该团队提出了一个基于 AFL，名为 [Intriguer](https://github.com/seclab-yonsei/intriguer) 的新型**混合 fuzzer**。通过污点分析和指令跟踪，经过笔者实践，该工具能够覆盖更深层次的代码路径。但是同时也存在 bug，会在 `/tmp` 目录下生成大量冗余文件。
- [Unicorefuzz: On the Viability of Emulation for Kernelspace Fuzzing](https://www.usenix.org/system/files/woot19-paper_maier.pdf) ：柏林工业大学学者发表在安全顶会  **USENIX Security '19**  上的一篇关于 **fuzzing 内核**的文章。相对于 syzkaller， [unicorefuzz](https://github.com/fgsect/unicorefuzz) 配置更加简单，能够 fuzz 路径较深的一些函数。
- [libFuzzer](http://llvm.org/docs/LibFuzzer.html) ：谷歌开发的一个基于覆盖引导的 fuzzer，主要针对库提供的**接口**进行 fuzzing。
- [Honggfuzz](https://github.com/google/honggfuzz)：同样是谷歌开发的一个类似于 afl 的工具，只是 honggfuzz 基于反馈驱动，多线程和多进程，fuzz 速度相比于 afl 有一个质的飞跃。
- [syzkaller](https://github.com/google/syzkaller)：优秀的**内核 fuzz** 工具，可以针对各种**驱动接口**进行 fuzzing。
- [frida-fuzzer](https://github.com/andreafioraldi/frida-fuzzer)： Frida-Fuzzer 是一款针对 API 的内存模糊测试框架，该工具的设计和开发灵感来源于 afl/afl++，Frida-Fuzzer 的当前版本支持在 GNU/Linux x86_64 和 Android x86——64 平台上运行。 
- [winafl](https://github.com/googleprojectzero/winafl)：afl 的一个分支项目，将 afl 用于Windows 平台。
- [trinity](https://github.com/kernelslacker/trinity)：Linux system call fuzzer，对于 **Linux 系统调用**的模糊测试工具。
- [NtCall64](https://github.com/hfiref0x/NtCall64)：Windows NT x64 syscall fuzzer，基于 NtCall 的 **Windows 系统调用**模糊测试工具。
- [kDriver-Fuzzer](https://github.com/k0keoyo/kDriver-Fuzzer)：基于 ioctlbf 框架编写的驱动漏洞挖掘工具 kDriver Fuzzer，**驱动 fuzzer**。
- [fuzzball](https://github.com/bitblaze-fuzzball/fuzzball)：FuzzBALL是基于 BitBlaze Vine 库的x86（和少许ARM）二进制代码的**符号执行**工具 

### API/协议

- [Sulley](https://github.com/OpenRCE/sulley)/[Boofuzz](https://github.com/jtpereyda/boofuzz)：Sulley 是一个模糊测试框架。主要用于协议的 fuzz，如今已经不再维护。 [Boofuzz](https://github.com/jtpereyda/boofuzz) 是古老的 [Sulley](https://github.com/OpenRCE/sulley) 模糊测试框架的分支和后续版本。除了大量错误修复外，boofuzz 扩展更多新特性。
- [fuzzowski](https://github.com/nccgroup/fuzzowski)：基于 boofuzz 的网络协议模糊测试工具，基于 sulley 的数据变异。
- [Peach](https://github.com/MozillaSecurity/peach)：Peach 是 Michael  团队开发的一个模糊测试框架，最初为开源软件，后续部分核心测试套**商用**发布。Peach 专注于文件格式的 fuzz，同时针对各种协议的 fuzz 也十分友好。
- [Defensics](https://www.synopsys.com/software-integrity/security-testing/fuzz-testing.html)： Defensics 是一个基于变异的 fuzzing **商用**工具，简单而强大，广泛支持各种协议，具有成熟的测试套，也具有较强扩展性，用户可以通过模板创建属于自己的测试套。
- [bsSTORM](https://beyondsecurity.com/bestorm-and-the-sdl.html?cn-reloaded=1)：**商用工具**，覆盖完整的软件生命周期，看上去更擅长协议 fuzz。
- [API-fuzzer](https://github.com/Fuzzapi/API-fuzzer)：使用常见的渗透测试技术和已知漏洞对一些网络 **API** 请求进行 fuzz。
- [domato](https://github.com/googleprojectzero/domato) ：googleprojectzero 开发的一个专门用于浏览器的黑盒 fuzz 工具，用法简单，通过让浏览器访问生成各种随机的前端页面，观察浏览器的状态。

### 固件

- [LABRADOR: Response Guided Directed Fuzzing for Black-box IoT Devices, 2024](https://www.computer.org/csdl/proceedings-article/sp/2024/313000a127/1Ub23HQTJ1C) - 又是一个针对固件黑盒 Fuzz 的工具，来自于信息工程大学的[Hangtian Liu](https://www.computer.org/csdl/search/default?type=author&givenName=Hangtian&surname=Liu)，也是张超团队的工作。相比 SNIPUZZ、BOOFUZZ 和 FIRM-AFL 能够发现更多的漏洞，同时是 SaTC 发现的漏洞的 8.57 倍。与以前工作不同的是，**LABRADOR 似乎不需要进行固件仿真**，而是在真机上进行 Fuzz 测试，通过网络响应来推断固件的执行跟踪，并推导出测试的代码覆盖率，未见开源。
- [Poster: Combining Fuzzing with Concolic Execution for IoT Firmware Testing, 2023](https://dl.acm.org/doi/10.1145/3576915.3624373)：又是一个针对 **IoT 固件的 Fuzz** 工具。在以前固件模糊测试的基础上结合了符号执行。但是其限制仍然是目标固件要支持全系统仿真。因此，本篇论文仍然没有解决固件 Fuzz 测试的核心问题，即仿真，作者来自于韩国世宗大学。
- [Forming Faster Firmware Fuzzers, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/seidel) - *柏林工业大学* Lukas Seidel 提出一种针对 **ARM Cortex-M MCU** 固件进行 Fuzz 的工具，[SAFIREFUZZ](https://github.com/pr0me/SAFIREFUZZ) 已开源，论文总结了过去的 MCU Fuzz 类型，并展现 SAFIREFUZZ 与众不同的地方：SAFIREFUZZ 运行在与目标固件架构相同的操作系统上（例如树莓派），节省了以前的工具使用 QEMU TCG 带来的性能损失，且不需要使用 softmmu，显著提升模糊测试效率。
- [FirmSolo: Enabling dynamic analysis of binary Linux-based IoT kernel modules, 2023](https://www.usenix.org/conference/usenixsecurity23/presentation/angelakopoulos) - *波士顿大学* Ioannis Angelakopoulos 工程师介绍的另外一种 IoT 固件模糊测试解决方案 FirmSolo。以经典的 Firmadyne 为例，传统固件模拟工具专注于用户空间的仿真和测试。而 FirmSole 可以提取固件的内核模块元信息，生成一个可以由 Qemu 加载的新内核，进而可以对这些内核模块进行模糊测试，已开源 [FirmSole ](https://github.com/BUseclab/FirmSolo)。
- [Fuzzware: Using Precise MMIO Modeling for Effective Firmware Fuzzing, 2022](https://www.usenix.org/conference/usenixsecurity22/presentation/scharnowski) -  使用精准的 MMIO 建模提高固件模糊测试效率，来自于*波鸿鲁尔大学* 。一种针对 **ARM Cortex-M MCU 固件**进行 Fuzz 的工具，使用 **Unicore Engine** 仿真，MMIO 寄存器作为 Fuzz 入口，已开源 [Fuzzware](https://github.com/fuzzware-fuzzer/fuzzware)。 
- [Automatic Firmware Emulation through Invalidity-guided Knowledge Inference, 2021](https://www.usenix.org/conference/usenixsecurity21/presentation/zhou) - 华中科技大学周威老师团队开发的 μEmu，使用**符号执行**获取**模拟固件映像**所需信息，支持 **ARM Cortex-M MCU 固件**，基于 **S2E**（符号执行平台）设计和开发的，已开源 [μEmu](https://github.com/MCUSec/uEmu)。
- [IOTFUZZER: Discovering Memory Corruptions in IoT Through App-based Fuzzing](https://www.ndss-symposium.org/wp-content/uploads/2018/02/ndss2018_01A-1_Chen_paper.pdf)：香港大学  Jiongyi Chen  发表在 **NDSS 2018** 上的一篇关于固件 fuzzing 的文章，作者借助 IoT 设备的移动端 App 设计了一个黑盒模糊测试工具 [IOTFuzzer](https://github.com/zyw-200/IOTFuzzer_Full) 分析 IoT 设备上的内存错误漏洞。通过测试了 17 个不同的 IoT 设备，最终发现 15 个内存错误漏洞，其中包括了 8 个未知的漏洞。
- [FIRM-AFL: High-Throughput Greybox Fuzzing of IoT Firmware via Augmented Process Emulation](https://www.usenix.org/conference/usenixsecurity19/presentation/zheng)：由中科院信工所 Yaowen Zheng 发表在 **USENIX Security '19** ， [FIRM-AFL](https://github.com/zyw-200/FirmAFL) 是第一个用于物联网固件的高质量灰盒模糊器，此工具的劣势在于只能 fuzz Firmadyne 能够正常模拟的固件。
- [FIRMCORN: Vulnerability-Oriented Fuzzing of IoT Firmware via Optimized Virtual Execution](https://ieeexplore.ieee.org/document/8990098)：发表在  [IEEE Access](https://ieeexplore.ieee.org/xpl/RecentIssue.jsp?punumber=6287639) 2020 年的期刊上，作为基于优化虚拟执行的 IoT 固件模糊测试框架 [FIRMCORN](https://github.com/FIRMCORN-Fuzzing/FIRMCORN)，作者声称是首次面向 IoT 固件的模糊测试框架。

## 4 Blogs

如果不想看这么多理论知识，只是想快速将工具运用于实际项目中，直接参考以下博客，即可对各种 fuzzing 工具快速入门。

**AFL**

- [AFL漏洞挖掘技术漫谈（一）：用AFL开始你的第一次Fuzzing](https://www.freebuf.com/articles/system/191543.html)
- [AFL漏洞挖掘技术漫谈（二）：Fuzz结果分析和代码覆盖率](https://www.freebuf.com/articles/system/197678.html) 
- [深入分析 afl / qemu-mode(qemu模式) / afl-unicorn 编译及安装存在的问题以及相应的解决方案](https://blog.csdn.net/song_lee/article/details/105082092)
- [AFL二三事——源码分析（上篇）](https://xz.aliyun.com/t/10315)
- [AFL二三事——源码分析（下篇）](https://xz.aliyun.com/t/10316)

**boofuzz**

- [IoT 设备网络协议模糊测试工具boofuzz实战](https://blog.csdn.net/song_lee/article/details/104334096)

**libfuzzer**

- [fuzz实战之libfuzzer](https://www.secpulse.com/archives/71898.html)

**Peach**

- [深入探究文件Fuzz工具之Peach实战](https://www.freebuf.com/sectool/120650.html) 
- [工控网络协议模糊测试：用peach对modbus协议进行模糊测试](https://cloud.tencent.com/developer/article/1093368)
- [Peach原理简介与实战：以Fuzz Web API为例](https://www.freebuf.com/sectool/219584.html) 

**内核 fuzz**

-  [内核漏洞挖掘技术系列(1)——trinity](https://xz.aliyun.com/t/4760) 
-  [内核漏洞挖掘技术系列(2)——bochspwn](https://xz.aliyun.com/t/4800) 
-  [内核漏洞挖掘技术系列(3)——bochspwn-reloaded(1)](https://xz.aliyun.com/t/4921)
-  [内核漏洞挖掘技术系列(3)——bochspwn-reloaded(2)](https://xz.aliyun.com/t/4932) 
-  [内核漏洞挖掘技术系列(4)——syzkaller(1)](https://xz.aliyun.com/t/5079) - syzkaller源码分析系列文章
-  [Syzkaller入门知识总结](https://www.freebuf.com/sectool/323886.html) - syzkaller 入门
-  [从0开始Fuzzing之旅: 使用Syzkaller进行Linux驱动漏洞挖掘](https://www.freebuf.com/sectool/285699.html) - Android 模拟器内核
-  [从0到1开始使用syzkaller进行Linux内核漏洞挖掘](https://bbs.pediy.com/thread-265405.htm) - Linux 内核
-  [Fuzzing a Pixel 3a Kernel with Syzkaller](https://blog.senyuuri.info/2020/04/16/fuzzing-a-pixel-3a-kernel-with-syzkaller/) - Android 手机

其他

- [基于 Unicorn 和 LibFuzzer 的模拟执行 fuzzing](http://galaxylab.com.cn/%e5%9f%ba%e4%ba%8eunicorn%e5%92%8clibfuzzer%e7%9a%84%e6%a8%a1%e6%8b%9f%e6%89%a7%e8%a1%8cfuzzing/) (2019)： 银河实验室对基于 unicorn 的模拟执行 fuzzing 技术进行了研究。在上次研究的基础上，进一步整合解决了部分问题，初步实现了基于 Unicorn 和 LibFuzzer 的模拟执行fuzzing 工具：[uniFuzzer](https://github.com/PAGalaxyLab/uniFuzzer)
- [IoT固件Rehosting综述](https://www.freebuf.com/articles/endpoint/335783.html) - **一篇相当不错的固件模拟综述**

<br />
<hr />

## Contribute

如果你看到了认为比较好的有关模糊测试的资源，欢迎贡献本项目！请阅读[贡献指南](https://github.com/liyansong2018/fuzzing-tutorial/blob/main/CONTRIBUTING.md)。

## License

<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/"><img alt="知识共享许可协议" style="border-width:0" src="https://i.creativecommons.org/l/by-sa/4.0/88x31.png" /></a><br />本作品采用<a rel="license" href="http://creativecommons.org/licenses/by-sa/4.0/">知识共享署名-相同方式共享 4.0 国际许可协议</a>进行许可。
