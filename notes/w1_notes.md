<h1>Summary</h1>

- [Resources](#resources)
  - [Phishing-related](#phishing-related)
  - [Domain/URL-related](#domainurl-related)
  - [Misc resources](#misc-resources)
- [Phishing Detection](#phishing-detection)
  - [Phishing Websites](#phishing-websites)
    - [Content-based](#content-based)
    - [URL-based](#url-based)
    - [Domain-based](#domain-based)
    - [Hybrid](#hybrid)
  - [Phishing e-mails](#phishing-e-mails)
    - [Content-based](#content-based-1)
  - [SMS Phishing](#sms-phishing)
    - [Content-based](#content-based-2)
- [Phishing Evasion](#phishing-evasion)
  - [Phishing Websites](#phishing-websites-1)
    - [URL-based](#url-based-1)
- [Surveys \& Benchmarks](#surveys--benchmarks)

# Resources

## Phishing-related

- 🆓 [PhishTank](https://phishtank.org/) is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.
- 🆓 [OpenPhish](https://openphish.com/) provides actionable intelligence data on active phishing threats.
- 🆓 [CheckPhish](https://checkphish.bolster.ai/) detects and Monitors Phishing and Scam Sites.

## Domain/URL-related

- ~~🆓 [Alexa](https://alexa.com/), also referred to as Global Rank by Alexa Internet and was designed to be an estimate of a website's popularity.. In December 2021, Amazon announced that it would be shutting down its Alexa Internet subsidiary. The service was then discontinued on May 1, 2022.~~
- 🆓/💲 [DomainTools](https://www.domaintools.com/) is the global leader in Internet intelligence. Learn how our products and data are fundamental to best-in-class security programs.
- 🆓 [WHOIS](https://who.is): Find information on any domain name or website. Large database of whois information, DNS, domain names, name servers, IPs, etc.
- 🆓 [VirusTotal](https://www.virustotal.com/): Analyse suspicious files, domains, IPs and URLs to detect malware and other breaches, automatically share them with the security community.

- 🆓/💲 [URLScan](https://urlscan.io/): Website scanner for suspicious and malicious URLs.

- 💲[ThreatConnect](https://threatconnect.com/) enables the operationalization of cyber threat intelligence analysis and management, and by leveraging native automation, orchestration, and knowledge capture, it lets teams work smarter, faster, and better – together.

## Misc resources

- [Easily Report Phishing and Malware](https://decentsecurity.com/#/malware-web-and-phishing-investigation/)

# Phishing Detection

## Phishing Websites

### Content-based

- Medvet, Eric, Engin Kirda, and Christopher Kruegel. “Visual-Similarity-Based Phishing Detection.” In Proceedings of the 4th International Conference on Security and Privacy in Communication Netowrks, 1–6. SecureComm ’08. New York, NY, USA: Association for Computing Machinery, 2008. https://doi.org/10.1145/1460877.1460905.

  "Signature" - quantitative way of capturing the information about the text and images that compose a web page - DOM. Comparison with some stored signature which represents the supposed legitimate website. Raise alerts if signatures are "too" similar.

- Abdelnabi, Sahar, Katharina Krombholz, and Mario Fritz. “VisualPhishNet: Zero-Day Phishing Website Detection by Visual Similarity.” In Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security, 1681–98. CCS ’20. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3372297.3417233.

  Use a visual-based approach instead of metadata features (these methods fail if attackers use images or embedded objects instead of HTML text. They are also vulnerable to code obfuscation techniques where a differentcode produces similar rendered images). Motivated by these reasons, we treated the problem as a similar-ity learning problem with deep learning using Siamese or tripletnetworks which have been successfully used in applications such as face verification, signature verification, and character recognition. In each of these applications, the identity of an image is compared against a database and the model verifies if this identity is matched with any of those in the database.

### URL-based

- Cuzzocrea, Alfredo, Fabio Martinelli, and Francesco Mercaldo. “A Machine-Learning Framework for Supporting Intelligent Web-Phishing Detection and Analysis.” In Proceedings of the 23rd International Database Applications & Engineering Symposium, 1–3. IDEAS ’19. New York, NY, USA: Association for Computing Machinery, 2019. https://doi.org/10.1145/3331076.3331087.

  Features from URL and networking properties of server. Comparison between different algorithms (J48, HoeffdingTree, RandomForest, RepTree, LMT, DecisionStump).

- Adap, Vielka Angela V., Gabriel A. Castillo, Erskine Jerrell M. Delos Reyes, Edward B. Ronquillo, and Larry A. Vea. “Do Not Feed the Phish: Phishing Website Detection Using URL-Based Features.” In Proceedings of the 2023 5th World Symposium on Software Engineering, 135–41. WSSE ’23. New York, NY, USA: Association for Computing Machinery, 2023. https://doi.org/10.1145/3631991.3632011.

  Classification of 48 URL-based features, using SOTA techniques (XGBoost, Random Forest).

- Aung, Eint Sandi, and Hayato Yamana. “Segmentation-Based Phishing URL Detection.” In IEEE/WIC/ACM International Conference on Web Intelligence and Intelligent Agent Technology, 550–56. WI-IAT ’21. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3486622.3493983.

  Premise: information-based features require no expert knowledge and are dataset-independent. Feature extraction by URL tokenization. Models used: biLSTM & CNNs.

- Alsarhan, Ayoub, Bashar Igried, Raad Mohammad Bani Saleem, Mohammad Alauthman, and Mohammad Aljaidi. “Enhancing Phishing URL Detection: A Comparative Study of Machine Learning Algorithms.” In Proceedings of the 2023 Asia Conference on Artificial Intelligence, Machine Learning and Robotics, 1–7. AIMLR ’23. New York, NY, USA: Association for Computing Machinery, 2023. https://doi.org/10.1145/3625343.3625348.

  Comparison between algorithms J48, JRip, Decision table, and Naïve Bayes by their result metrics using a common dataset.

- Kim, Taeri, Noseong Park, Jiwon Hong, and Sang-Wook Kim. “Phishing URL Detection: A Network-Based Approach Robust to Evasion.” In Proceedings of the 2022 ACM SIGSAC Conference on Computer and Communications Security, 1769–82. CCS ’22. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3548606.3560615.

  Network-based classification of features, with the purpose of training a model robust to evasion (building phishing sites on top of benign domains).

- Aung, Eint Sandi, and Hayato Yamana. “URL-Based Phishing Detection Using the Entropy of Non-Alphanumeric Characters.” In Proceedings of the 21st International Conference on Information Integration and Web-Based Applications & Services, 385–92. iiWAS2019. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3366030.3366064.

  Assumptions: URL-based > content-based; distribution of non-alphanumeric characters affects performance of classifiers. Proposal of feature "entropy of NAN characters".

- Blum, Aaron, Brad Wardman, Thamar Solorio, and Gary Warner. “Lexical Feature Based Phishing URL Detection Using Online Learning.” In Proceedings of the 3rd ACM Workshop on Artificial Intelligence and Security, 54–60. AISec ’10. New York, NY, USA: Association for Computing Machinery, 2010. https://doi.org/10.1145/1866423.1866434.

  Proposal of lexical-based features to classify phishing and legitimate URLs. Model: confidence-weighted classifier.

- Sirigineedi, Surya Srikar, Jayesh Soni, and Himanshu Upadhyay. “Learning-Based Models to Detect Runtime Phishing Activities Using URLs.” In Proceedings of the 2020 4th International Conference on Compute and Data Analysis, 102–6. ICCDA ’20. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3388142.3388170.

  Real-time detection, by extraction of lexical (URL) and host-based properties of a website (using NLP). Deep learning models: kNN, Logistic regresion, Support Vectos Machines, Gradient Boosting Classificer, Ada-boost Classifier, Random Forest Classifier.

- Valentim, Rodolfo, Idilio Drago, Martino Trevisan, Federico Cerutti, and Marco Mellia. “Augmenting Phishing Squatting Detection with GANs.” In Proceedings of the CoNEXT Student Workshop, 3–4. CoNEXT-SW ’21. New York, NY, USA: Association for Computing Machinery, 2021. https://doi.org/10.1145/3488658.3493787.

  Usage of GANs to generate a list of squatting candidates to train models to be resilient to evasion. Zero-day phishing attacks. Models: Long Short-Term Memory units, CNNs.

- ✨ Rashid, Fariza, Ben Doyle, Soyeon Caren Han, and Suranga Seneviratne. “Phishing URL Detection Generalisation Using Unsupervised Domain Adaptation.” Computer Networks 245 (May 1, 2024): 110398. https://doi.org/10.1016/j.comnet.2024.110398.

  URL-based detection methods lack generalization because often phishing URLs are freshly made and do not reside in a blacklist. Proposal of an Unsupervised Domain Adaptation-based Framework to increase model transferability between datasets.

- ✨ Vajrobol, Vajratiya, Brij B. Gupta, and Akshat Gaurav. “Mutual Information Based Logistic Regression for Phishing URL Detection.” Cyber Security and Applications 2 (January 1, 2024): 100044. https://doi.org/10.1016/j.csa.2024.100044.

  Selection of URL-based features relying on mutual information based logistic regression.

### Domain-based

- Shirazi, Hossein, Bruhadeshwar Bezawada, and Indrakshi Ray. “‘Kn0w Thy Doma1n Name’: Unbiased Phishing Detection Using Domain Name Based Features.” In Proceedings of the 23nd ACM on Symposium on Access Control Models and Technologies, 69–75. SACMAT ’18. New York, NY, USA: Association for Computing Machinery, 2018. https://doi.org/10.1145/3205977.3205992.

  Premise: domain nameof phishing websites isthe tell-tale sign of phishing and holds the key to successful phishing detection. Tested using classifiers (SVM linear, SVM Gaussian, Gaussian Naive Bayes, kNN, Decision tree, Gradient-boosting, Majority Voting).

- AlSabah, Mashael, Mohamed Nabeel, Yazan Boshmaf, and Euijin Choo. “Content-Agnostic Detection of Phishing Domains Using Certificate Transparency and Passive DNS.” In Proceedings of the 25th International Symposium on Research in Attacks, Intrusions and Defenses, 446–59. RAID ’22. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3545948.3545958.

  Argument: content-based & whitelist methods are evadable and reactive in nature. Proposal: creation of domain-based features such as CT logs and domain issuer/SAN-based characteristics.

### Hybrid

- Vo Quang, Minh, Dang Bui Tan Hai, Ngan Tran Kim Ngoc, Son Ngo Duc Hoang, Quyen Nguyen Huu, Duy Phan The, and Van-Hau Pham. “Shark-Eyes: A Multimodal Fusion Framework for Multi-View-Based Phishing Website Detection.” In Proceedings of the 12th International Symposium on Information and Communication Technology, 793–800. SOICT ’23. New York, NY, USA: Association for Computing Machinery, 2023. https://doi.org/10.1145/3628797.3629003.

  Combination of two classes of attributes: domain features & HTML tag features. Comparison by usage of datasets PhishTank, OpenPhish and Alexa. Model: CNNs, RNNs and LSTM.

- Siddiq, Md. Abu Ashraf, Mohammad Arifuzzaman, and M. S. Islam. “Phishing Website Detection Using Deep Learning.” In Proceedings of the 2nd International Conference on Computing Advancements, 83–88. ICCA ’22. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3542954.3542967.

  Model training using 68 features (URL-related, abnormal features, content-related and domain-related). Techniques: simple neural networks & CNNs.

- El Kouari, Oumaima, Hafssa Benaboud, and Saiida Lazaar. “Using Machine Learning to Deal with Phishing and Spam Detection: An Overview.” In Proceedings of the 3rd International Conference on Networking, Information Systems & Security, 1–7. NISS ’20. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3386723.3387891.

  Overview of some phishing detection techniques: content-based.

- Hajizada, Abulfaz, and Sharmin Jahan. “Feature Selections for Phishing URLs Detection Using Combination of Multiple Feature Selection Methods.” In Proceedings of the 2023 15th International Conference on Machine Learning and Computing, 444–50. ICMLC ’23. New York, NY, USA: Association for Computing Machinery, 2023. https://doi.org/10.1145/3587716.3587790.

  Feature reduction method arguing that this improves the model's detection accuracy.

- Adane, Kibreab, Berhanu Beyene, and Mohammed Abebe. “Single and Hybrid-Ensemble Learning-Based Phishing Website Detection: Examining Impacts of Varied Nature Datasets and Informative Feature Selection Technique.” Digital Threats: Research and Practice 4, no. 3 (October 6, 2023): 46:1-46:27. https://doi.org/10.1145/3611392.

  Implementation of hybrid approach (URL-based, content-based, domain-based and Page Rank based) to benchmark different types of classification techniques (CATB, RF, GB).

- Zeng, Victor, Xin Zhou, Shahryar Baki, and Rakesh M. Verma. “PhishBench 2.0: A Versatile and Extendable Benchmarking Framework for Phishing.” In Proceedings of the 2020 ACM SIGSAC Conference on Computer and Communications Security, 2077–79. CCS ’20. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3372297.3420017.

  Benchmarking tool to compare different methods, allows a code-based feature & hyperparameter specification. Models: 12 ML-based classifiers.

- ✨ Kamble, Naresh, and Dr. Nilamadhab Mishra. “Hybrid Optimization Enabled Squeeze Net For Phishing Attack Detection.” Computers & Security, May 14, 2024, 103901. https://doi.org/10.1016/j.cose.2024.103901.

  A deep learning model proposal which supposedly exhibits better metrics, compared to other alternatives.

- ✨ Geest, R. J. van, G. Cascavilla, J. Hulstijn, and N. Zannone. “The Applicability of a Hybrid Framework for Automated Phishing Detection.” Computers & Security 139 (April 1, 2024): 103736. https://doi.org/10.1016/j.cose.2024.103736.

  Proposal of a hybrid framework to leverage multiple detection models simultaneously, which achieves better performance with less computational time.

- ✨ Zhu, Erzhou, Kang Cheng, Zhizheng Zhang, and Huabin Wang. “PDHF: Effective Phishing Detection Model Combining Optimal Artificial and Automatic Deep Features.” Computers & Security 136 (January 1, 2024): 103561. https://doi.org/10.1016/j.cose.2023.103561.

  Proposal of a set of deep features, that intend to reduce the impact of adaptation by phishing attackers, while also removing redundant features.

- ✨ Prasad, Arvind, and Shalini Chandra. “PhiUSIIL: A Diverse Security Profile Empowered Phishing URL Detection Framework Based on Similarity Index and Incremental Learning.” Computers & Security 136 (January 1, 2024): 103545. https://doi.org/10.1016/j.cose.2023.103545.

  Proposal of a detection framework based on Similarity Index and Incremental Learning, which extracts features from both URL and HTML. This framework shows better performance than other techniques.

- ✨ Bahaghighat, Mahdi, Majid Ghasemi, and Figen Ozen. “A High-Accuracy Phishing Website Detection Method Based on Machine Learning.” Journal of Information Security and Applications 77 (September 1, 2023): 103553. https://doi.org/10.1016/j.jisa.2023.103553.

  Comparison of different ML-based techniques (Logistic Regression, K-Nearest Neighbors, Naïve-Bayes, Random Forest, Support Vector Machines, XGBoost) to predict if a website is phishing or not, by extracting features from URL and domain.

- ✨ Tan, Colin Choon Lin, Kang Leng Chiew, Kelvin S. C. Yong, Yakub Sebastian, Joel Chia Ming Than, and Wei King Tiong. “Hybrid Phishing Detection Using Joint Visual and Textual Identity.” Expert Systems with Applications 220 (June 15, 2023): 119723. https://doi.org/10.1016/j.eswa.2023.119723.

  Proposal of an improved identity-based detection technique, which aims to reduce false positives (they often occur due to complexities and challenges in establishing a webpage's brand identity).

- ✨ Abdullah Alohali, Manal, Naif Alasmari, Mashael Maashi, Amal M. Nouri, Mohammed Rizwanullah, Ishfaq Yaseen, Azza Elneil Osman, and Amani A. Alneil. “Metaheuristics with Deep Learning Driven Phishing Detection for Sustainable and Secure Environment.” Sustainable Energy Technologies and Assessments 56 (March 1, 2023): 103114. https://doi.org/10.1016/j.seta.2023.103114.

  Proposal of an end-to-end technique that has systematic methods of dataset preprocessing, feature selection as well as hyperparameter tuning (based on LTSM).

- ✨ Asiri, Sultan, Yang Xiao, Saleh Alzahrani, and Tieshan Li. “PhishingRTDS: A Real-Time Detection System for Phishing Attacks Using a Deep Learning Model.” Computers & Security 141 (June 1, 2024): 103843. https://doi.org/10.1016/j.cose.2024.103843.

  Real-time detection by means of processing the website in a container, triggered via browser extension. BiLSTM.

- ✨ Sánchez-Paniagua, Manuel, Eduardo Fidalgo, Enrique Alegre, and Rocío Alaiz-Rodríguez. “Phishing Websites Detection Using a Novel Multipurpose Dataset and Web Technologies Features.” Expert Systems with Applications 207 (November 30, 2022): 118010. https://doi.org/10.1016/j.eswa.2022.118010.

  Proposal of a feature selection that is supposedly novel, using a LightGBM classifier.

- ✨ Liu, Dong-Jie, Guang-Gang Geng, and Xin-Chang Zhang. “Multi-Scale Semantic Deep Fusion Models for Phishing Website Detection.” Expert Systems with Applications 209 (December 15, 2022): 118305. https://doi.org/10.1016/j.eswa.2022.118305.

  Proposal of three detection models based on semantic information about websites.

- ✨ Hussain, Musarat, Chi Cheng, Rui Xu, and Muhammad Afzal. “CNN-Fusion: An Effective and Lightweight Phishing Detection Method Based on Multi-Variant ConvNet.” Information Sciences 631 (June 1, 2023): 328–45. https://doi.org/10.1016/j.ins.2023.02.039.

  Proposal of a combination of CNN models to offer lightweight detection and some other optimizations.

- ✨ Wazirali, Raniyah, Rami Ahmad, and Ashraf Abdel-Karim Abu-Ein. “Sustaining Accurate Detection of Phishing URLs Using SDN and Feature Selection Approaches.” Computer Networks 201 (December 24, 2021): 108591. https://doi.org/10.1016/j.comnet.2021.108591.

  Proposal of different optimization techniques (feature selection, based on Software Defined Network technologies).

- ✨ Alani, Mohammed M., and Hissam Tawfik. “PhishNot: A Cloud-Based Machine-Learning Approach to Phishing URL Detection.” Computer Networks 218 (December 9, 2022): 109407. https://doi.org/10.1016/j.comnet.2022.109407.

  A proposal of feature and model selections intended to provide good performance with high speed detection (~11 μs/website).

- ✨ Liu, Dong-Jie, Guang-Gang Geng, Xiao-Bo Jin, and Wei Wang. “An Efficient Multistage Phishing Website Detection Model Based on the CASE Feature Framework: Aiming at the Real Web Environment.” Computers & Security 110 (November 1, 2021): 102421. https://doi.org/10.1016/j.cose.2021.102421.

  Proposal of a multistage detection model based on the CASE feature framework.

- ✨ Wang, Chenguang, and Yuanyuan Chen. “TCURL: Exploring Hybrid Transformer and Convolutional Neural Network on Phishing URL Detection.” Knowledge-Based Systems 258 (December 22, 2022): 109955. https://doi.org/10.1016/j.knosys.2022.109955.

  Proposal of a hybrid network architecture, which aims to reduce the disadvantages of Deep Learning models.

- ✨ Zhu, Erzhou, Yinyin Ju, Zhile Chen, Feng Liu, and Xianyong Fang. “DTOF-ANN: An Artificial Neural Network Phishing Detection Model Based on Decision Tree and Optimal Features.” Applied Soft Computing 95 (October 1, 2020): 106505. https://doi.org/10.1016/j.asoc.2020.106505.

  Systematic feature selection approach, to improve performance of Deep Learning models by means of reducing overfitting and other limitations.

## Phishing e-mails

### Content-based

- Aggarwal, Shivam, Vishal Kumar, and S. D. Sudarsan. “Identification and Detection of Phishing Emails Using Natural Language Processing Techniques.” In Proceedings of the 7th International Conference on Security of Information and Networks, 217–22. SIN ’14. New York, NY, USA: Association for Computing Machinery, 2014. https://doi.org/10.1145/2659651.2659691.

  Proposal of some natural language features inside an e-mail content (absence of names, mention of money, presence of a reply inducing sentence, sense of urgency) to create a classification by NLP and tell apart phishing from non-phishing e-mails.

- Mehdi Gholampour, Parisa, and Rakesh M. Verma. “Adversarial Robustness of Phishing Email Detection Models.” In Proceedings of the 9th ACM International Workshop on Security and Privacy Analytics, 67–76. IWSPA ’23. New York, NY, USA: Association for Computing Machinery, 2023. https://doi.org/10.1145/3579987.3586567.

  Creation of an augmented adversarial dataset to benchmark different Transformer models.

- Bountakas, Panagiotis, Konstantinos Koutroumpouchos, and Christos Xenakis. “A Comparison of Natural Language Processing and Machine Learning Methods for Phishing Email Detection.” In Proceedings of the 16th International Conference on Availability, Reliability and Security, 1–12. ARES ’21. New York, NY, USA: Association for Computing Machinery, 2021. https://doi.org/10.1145/3465481.3469205.

  Comparison of Natural Language Processing (TF-IDF, Word2Vec, and BERT) and Machine Learning (Random Forest, Decision Tree, LogisticRegression, Gradient Boosting Trees, and Naive Bayes) techniques for phishing detection.

- Qachfar, Fatima Zahra, Rakesh M. Verma, and Arjun Mukherjee. “Leveraging Synthetic Data and PU Learning For Phishing Email Detection.” In Proceedings of the Twelfth ACM Conference on Data and Application Security and Privacy, 29–40. CODASPY ’22. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3508398.3511524.

  Generation of synthetic text and application of PU learning to create a robust to evasion model.

## SMS Phishing

### Content-based

- Ulfath, Rubaiath E, Hamed Alqahtani, Mohammad Hammoudeh, and Iqbal H. Sarker. “Hybrid CNN-GRU Framework with Integrated Pre-Trained Language Transformer for SMS Phishing Detection.” In The 5th International Conference on Future Networks & Distributed Systems, 244–51. ICFNDS 2021. New York, NY, USA: Association for Computing Machinery, 2022. https://doi.org/10.1145/3508072.3508109.

  Raw SMS content is lemmatized to extract features, using CNN and bi-directional GRU (Gated Recurrent Units). "RQ: How can we handle non-linearity,variability in-text features and minimize computing complexitywhile discovering robust discriminating characteristics to combatever-increasing phishing attacks?"

# Phishing Evasion

## Phishing Websites

### URL-based

- AlEroud, Ahmed, and George Karabatis. “Bypassing Detection of URL-Based Phishing Attacks Using Generative Adversarial Deep Neural Networks.” In Proceedings of the Sixth International Workshop on Security and Privacy Analytics, 53–60. IWSPA ’20. New York, NY, USA: Association for Computing Machinery, 2020. https://doi.org/10.1145/3375708.3380315.

  Generative Adversarial Deep Neural Networks. The results show that GAN networks are very effective in creating adversarial phishing examples that can fool both simple and sophisticated machine learning phishing detection models.

# Surveys & Benchmarks

- ✨ Safi, Asadullah, and Satwinder Singh. “A Systematic Literature Review on Phishing Website Detection Techniques.” Journal of King Saud University - Computer and Information Sciences 35, no. 2 (February 1, 2023): 590–611. https://doi.org/10.1016/j.jksuci.2023.01.004.

  SLR of 80 recent works. The survey revealed that while gathering the data sets, researchers primarily accessed two sources: 53 studies accessed the PhishTank website (53 for the phishing data set) and 29 studies used Alexa's website for downloading legitimate data sets. Also, as per the literature survey, most studies used Machine Learning techniques; 31 used Random Forest Classifier. Finally, as per different studies, Convolution Neural Network (CNN) achieved the highest Accuracy, 99.98%, for detecting phishing websites.

- ✨ Ojewumi, T. O., G. O. Ogunleye, B. O. Oguntunde, O. Folorunsho, S. G. Fashoto, and N. Ogbu. “Performance Evaluation of Machine Learning Tools for Detection of Phishing Attacks on Web Pages.” Scientific African 16 (July 1, 2022): e01165. https://doi.org/10.1016/j.sciaf.2022.e01165.

  Evaluation of different ML-based techniques for phishing detection (14 features; kNN, RF, SVM algorithms).

- ✨ Vrbančič, Grega, Iztok Fister, and Vili Podgorelec. “Datasets for Phishing Websites Detection.” Data in Brief 33 (December 1, 2020): 106438. https://doi.org/10.1016/j.dib.2020.106438.

  Collection of datasets for phishing detection.