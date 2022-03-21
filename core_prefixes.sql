PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;
CREATE TABLE IF NOT EXISTS "core_prefixes" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "username" varchar(100) NOT NULL, "prefix" varchar(5) NOT NULL, "registration_date" datetime NOT NULL, "registration_certificate" varchar(1000) NOT NULL);
INSERT INTO core_prefixes VALUES(1,'jonathon.keeney@gmail.com','AWS','2020-12-14 19:36:01','93d836ebcfcc41f6817b36810082eb78');
INSERT INTO core_prefixes VALUES(2,'keeneyjg@gwu.edu','CIT','2020-12-14 19:36:01','1c8ff7f5f4864022886166b083e684f9');
INSERT INTO core_prefixes VALUES(3,'keeneyjg@gwu.edu','CAP','2020-12-14 19:36:01','4f191aec8ae0472591fb4b341e99f200');
INSERT INTO core_prefixes VALUES(4,'mazumder@gwu.edu','BCO','2020-12-14 19:36:01','56a369599f4d42bda047963ada468ed6');
INSERT INTO core_prefixes VALUES(5,'keeneyjg@gwu.edu','CC','2020-12-14 19:36:01','29c9fa47665a4242b2cf9a9366de9966');
INSERT INTO core_prefixes VALUES(6,'keeneyjg@gwu.edu','CDC','2020-12-14 19:36:01','130d8486529548ae9d77767d79132111');
INSERT INTO core_prefixes VALUES(7,'keeneyjg@gwu.edu','CLIA','2020-12-14 19:36:01','f488b45594054e1fafc213e6926aec97');
INSERT INTO core_prefixes VALUES(8,'hadley_king@gwu.edu','COVID','2020-12-14 19:36:01','37ccddd1eb2b40acb7da7f77182ec10a');
INSERT INTO core_prefixes VALUES(9,'keeneyjg@gwu.edu','EPA','2020-12-14 19:36:01','6895b247fec84cbfbe30b9fbc4ccbe36');
INSERT INTO core_prefixes VALUES(10,'keeneyjg@gwu.edu','CSR','2020-12-14 19:36:01','81758be3d0ed4118adf8a11e702a35fd');
INSERT INTO core_prefixes VALUES(11,'keeneyjg@gwu.edu','FIC','2020-12-14 19:36:01','44509af8d44f4eea9662ebf3416489b3');
INSERT INTO core_prefixes VALUES(12,'keeneyjg@gwu.edu','FDA','2020-12-14 19:36:01','f22a9133501140ff9cc54ee4db2de5ac');
INSERT INTO core_prefixes VALUES(13,'jeetvora@gwu.edu','GLY','2020-12-14 19:36:01','ab0b6da5899b4344a155911f0997a89f');
INSERT INTO core_prefixes VALUES(14,'keeneyjg@gwu.edu','GWU','2020-12-14 19:36:01','2b1ec43870924df5b0e351d44491add8');
INSERT INTO core_prefixes VALUES(15,'mazumder@gwu.edu','HIVE','2020-12-14 19:36:01','e9c3677d9c854cdf8328830e277416cf');
INSERT INTO core_prefixes VALUES(16,'tan5um@virginia.edu','HIVE1','2020-12-14 19:36:01','d6c3f6949b494fb9acccba831c6e30b8');
INSERT INTO core_prefixes VALUES(17,'keeneyjg@gwu.edu','NCCIH','2020-12-14 19:36:01','cdef03441753435c9636ed1f4b4c24d1');
INSERT INTO core_prefixes VALUES(18,'keeneyjg@gwu.edu','NCATS','2020-12-14 19:36:01','424a19e262564b4790580e5d2edb08d4');
INSERT INTO core_prefixes VALUES(19,'keeneyjg@gwu.edu','NCI','2020-12-14 19:36:01','628cb44cc23a4b0693992247a3cc6807');
INSERT INTO core_prefixes VALUES(20,'keeneyjg@gwu.edu','NHGRI','2020-12-14 19:36:01','71aa3ca0bd7a4fa38199806357380495');
INSERT INTO core_prefixes VALUES(21,'keeneyjg@gwu.edu','NHLBI','2020-12-14 19:36:01','faf999d8c839494bb6fde999757ee6bb');
INSERT INTO core_prefixes VALUES(22,'keeneyjg@gwu.edu','NEI','2020-12-14 19:36:01','6cde428fa5a74b17b4382fe98ea8ade4');
INSERT INTO core_prefixes VALUES(23,'keeneyjg@gwu.edu','NIA','2020-12-14 19:36:01','d88513ed17734d03a1a2dfd34d984f32');
INSERT INTO core_prefixes VALUES(24,'keeneyjg@gwu.edu','NIAAA','2020-12-14 19:36:01','911bfb0081f9475a9e0b1dc48cd86d54');
INSERT INTO core_prefixes VALUES(25,'keeneyjg@gwu.edu','NIAID','2020-12-14 19:36:01','8faaf0c866a147c0845412effb000bcb');
INSERT INTO core_prefixes VALUES(26,'keeneyjg@gwu.edu','NIBIB','2020-12-14 19:36:01','8f4d54fb2a414d65a1b1ff4efa57391f');
INSERT INTO core_prefixes VALUES(27,'keeneyjg@gwu.edu','NICHD','2020-12-14 19:36:01','f9806946229d4fce9a5b1ea019fd384c');
INSERT INTO core_prefixes VALUES(28,'keeneyjg@gwu.edu','NIDA','2020-12-14 19:36:01','40e44d503ec742e681d157a4721d6c83');
INSERT INTO core_prefixes VALUES(29,'keeneyjg@gwu.edu','NIDCD','2020-12-14 19:36:01','d086e7ac53d9443daf62545cd4924fe1');
INSERT INTO core_prefixes VALUES(30,'keeneyjg@gwu.edu','NIDCR','2020-12-14 19:36:01','8795c71e99d64a04863403b22cba4a0a');
INSERT INTO core_prefixes VALUES(31,'keeneyjg@gwu.edu','NIDDK','2020-12-14 19:36:01','ba3003869ace45a4a8d5fe3593cf7dfb');
INSERT INTO core_prefixes VALUES(32,'keeneyjg@gwu.edu','NIEHS','2020-12-14 19:36:01','e59e1dedc46d451e8dd36f794d60c628');
INSERT INTO core_prefixes VALUES(33,'keeneyjg@gwu.edu','NIH','2020-12-14 19:36:01','766e895b9bcd4a82b1c52a24b101c01b');
INSERT INTO core_prefixes VALUES(34,'keeneyjg@gwu.edu','NIMH','2020-12-14 19:36:01','5cc668fe57ff4120bcf480c09588092f');
INSERT INTO core_prefixes VALUES(35,'keeneyjg@gwu.edu','NIMHD','2020-12-14 19:36:01','d33b9d04dd69411aa0d316abd12a9bee');
INSERT INTO core_prefixes VALUES(36,'keeneyjg@gwu.edu','NINDS','2020-12-14 19:36:01','1be9871bad5f4a49bd56bd64546a9cf7');
INSERT INTO core_prefixes VALUES(37,'keeneyjg@gwu.edu','NINR','2020-12-14 19:36:01','cbe5ef4f558a4b83bc3fc63c7e818005');
INSERT INTO core_prefixes VALUES(38,'keeneyjg@gwu.edu','NLM','2020-12-14 19:36:01','a86248425ace467dbd02778700033e1c');
INSERT INTO core_prefixes VALUES(39,'keeneyjg@gwu.edu','NIAMS','2020-12-14 19:36:01','66b4efe748324214a74105d9d09024a1');
INSERT INTO core_prefixes VALUES(40,'keeneyjg@gwu.edu','NIGMS','2020-12-14 19:36:01','844dfd1a15b34b6680149a6b67a85d94');
INSERT INTO core_prefixes VALUES(41,'keeneyjg@gwu.edu','OHSU','2020-12-14 19:36:01','c63d0cc6717f4911bb0adf95a742d553');
INSERT INTO core_prefixes VALUES(42,'amandab2140@gwu.edu','OMX','2020-12-14 19:36:01','2dccb03fc03047ac9c9a88200d178cd5');
INSERT INTO core_prefixes VALUES(43,'tan5um@virginia.edu','TEST','2020-12-14 19:36:01','dafc3b6e6cc94edc9d4a4637204a5506');
INSERT INTO core_prefixes VALUES(44,'keeneyjg@gwu.edu','TEST1','2020-12-14 19:36:01','4bc5333e11694af7bfbd1ae40e1b48d5');
INSERT INTO core_prefixes VALUES(45,'keeneyjg@email.gwu.edu','TEST2','2020-12-14 19:36:01','1dabc8be099b4a3da300b5513bd132ed');
INSERT INTO core_prefixes VALUES(46,'teasod@aasd','TEST3','2020-12-14 19:36:01','8661c8ab76d94e039216908ab524ba0f');
INSERT INTO core_prefixes VALUES(47,'tan5um@virginia.edu','TEST4','2020-12-14 19:36:01','0d55c2e9292d4c7b93dd89e29b72c20a');
INSERT INTO core_prefixes VALUES(48,'keeneyjg@gwu.edu','OD','2020-12-14 19:36:01','10fd0fd9b3db4d919c778b7d87d79ae0');
INSERT INTO core_prefixes VALUES(49,'tan5um@virginia.edu','TEST6','2020-12-14 19:36:01','f7c56e3ea091479eb90f622fcc415c38');
INSERT INTO core_prefixes VALUES(50,'keeneyjg@gwu.edu','TEST7','2020-12-14 19:36:01','b361889be7da4fbcae3b53c576501bf7');
INSERT INTO core_prefixes VALUES(51,'stalwar@gwu.edu','TEST8','2020-12-14 19:36:01','a437292d01514aff936d403bd1a9d01d');
INSERT INTO core_prefixes VALUES(52,'stalwar@gwu.edu','TEST9','2020-12-14 19:36:01','a26d969a81f14aaf8a4d7646a3392203');
INSERT INTO core_prefixes VALUES(53,'stalwar@gwu.edu','TST1','2020-12-14 19:36:01','aba46c52b94743aebba4d7e84fce77f3');
INSERT INTO core_prefixes VALUES(54,'stalwar@gwu.edu','TST2','2020-12-14 19:36:01','dcfbb38e4db14d869b08110446344f0f');
INSERT INTO core_prefixes VALUES(55,'test@test.com','YO','2020-12-14 19:36:01','df2ef4dc10f240daa1e702a0fd2c1c87');
INSERT INTO core_prefixes VALUES(56,'keeneyjg@gwu.edu','TEST5','2020-12-14 19:36:01','69e7b4ba02564f9a9493ec953f78b218');
INSERT INTO core_prefixes VALUES(57,'er','WE','2021-05-19 17:54:37','545ff2781689449ea3864eea493e644e');
INSERT INTO core_prefixes VALUES(58,'erwerf','WEWER','2021-05-19 17:54:45','b3bb50aaf438479ebe42fa884c07cb0a');
COMMIT;