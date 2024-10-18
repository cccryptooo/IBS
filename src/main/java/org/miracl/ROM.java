/*
 * Copyright (c) 2012-2020 MIRACL UK Ltd.
 *
 * This file is part of MIRACL Core
 * (see https://github.com/miracl/core).
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Fixed Data in ROM - Field and Curve parameters */


package org.miracl;

public class ROM
{

// Base Bits= 58
public static final long[] Modulus= {0x1FEFFFFFFFFAAABL,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L};
public static final long[] ROI= {0x1FEFFFFFFFFAAAAL,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L};
public static final long[] R2modp= {0x20639A1D5BEF7AEL,0x1244C6462DD93E8L,0x22D09B54E6E2CD2L,0x111C4B63170E5DBL,0x38A6DE8FB366399L,0x4F16CFED1F9CBCL,0x19EA66A2BL};
public static final long MConst= 0x1F3FFFCFFFCFFFDL;
public static final long[] SQRTm3= {0x1FB00000001AAAEL,0x313F5FB4FFFFED7L,0x2928BFC912627L,0x1D87D988BA6AF26L,0x2845E1033EFA3BFL,0x25FF9A6633A3655L,0x1A0111EA3L};

public static final int CURVE_B_I= 4;
public static final int CURVE_Cof_I= 0;
public static final long[] CURVE_B= {0x4L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Order= {0x3FFFFFF00000001L,0x36900BFFF96FFBFL,0x180809A1D80553BL,0x14CA675F520CCE7L,0x73EDA7L,0x0L,0x0L};
public static final long[] CURVE_Gx= {0x33AF00ADB22C6BBL,0x17A0FFE5E86BBFEL,0x3A3F171BAC586C5L,0x13E5DD2E4168538L,0x4FA9AC0FC3688CL,0x65F5E509A558E3L,0x17F1D3A73L};
public static final long[] CURVE_Gy= {0xAA232946C5E7E1L,0x331D128A222B903L,0x18CB2C04B3EDD03L,0x25757402BD8036CL,0x1741D8AE4FCF5E0L,0xEAA83C68278C3BL,0x8B3F481EL};
public static final long[] CURVE_HTPC= {0xC51062BDE821B8L,0x1A5483B9715FEDFL,0x1BDD403FC31088BL,0x3D2523427FC11BBL,0x1A3D71BDA12F01DL,0x2DB2FDD36CE3D2AL,0x1F7462C8L};

public static final long[] Fra= {0x10775ED92235FB8L,0x3A94F58F9E04F63L,0x3D784BAB9C4F67L,0x3F4F2F57D3DEC91L,0x202C0D1F0FD603L,0xAEC199F08C6FADL,0x1904D3BF0L};
public static final long[] Frb= {0xF78A126DDC4AF3L,0x356B0535B1FB08BL,0xEC971F63C5F282L,0x21EDB1ECDBFB032L,0x2231F9FB854A147L,0x1B1380CA23A7A40L,0xFC3E2B3L};
public static final long[] CURVE_Bnx= {0x201000000010000L,0x34L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Cof= {0x201000000010001L,0x34L,0x0L,0x0L,0x0L,0x0L,0x0L};
//public static final long[] CURVE_Cof= {0xAAAB0000AAABL,0x3230015557855A3L,0x396L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CRu= {0x201FFFFFFFEFFFEL,0x1F604D88280008BL,0x293BE6F89688DE1L,0x1DA83DDFAB76CEL,0x3DF76CE51BA69C6L,0x17C659CBL,0x0L};
public static final long[] CURVE_Pxa= {0x8056C8C121BDB8L,0x300C9AA016EFBF5L,0xB647AE3D1770BAL,0x353E900EC0AD144L,0x32DC51051C6E47AL,0x23C2A449820149L,0x24AA2B2FL};
public static final long[] CURVE_Pxb= {0x1AC7D055D042B7EL,0x33C4484E51755F9L,0x21BBDC7F5049334L,0x3426482D86AD769L,0x88274F65596BD0L,0x9C67D81F6B34E8L,0x13E02B605L};
public static final long[] CURVE_Pya= {0x193548608B82801L,0x2B2730EEB28A278L,0x1A695160D12C923L,0x2AA32F74E9DB50AL,0x2DA2E351AADFD9BL,0x9F5B8463327371L,0xCE5D5277L};
public static final long[] CURVE_Pyb= {0x2A9075FF05F79BEL,0x1C349D73B07686AL,0x12AB572E99AB3F3L,0x1FA169D8EBC99D2L,0x2BC28B99CB3E28L,0x3A9CD330CAB34ACL,0x606C4A02L};

public static final long[] CURVE_Ad= {0xF428082D584C1DL,0xDBE368383E5FD7L,0x181AEFD881AC989L,0x14E0FB99AA363A2L,0x2C96D4982B0EA98L,0xEE3A50CF5A4E80L,0x144698AL};
public static final long[] CURVE_Bd= {0x1CC48E98E172BE0L,0xC8568C5B3AA974L,0x14FCEF35EF55A2L,0x3C3C93D01C282E7L,0x753EEE3B2016C1L,0x5A200C0062C4BAL,0x12E2908D1L};
public static final long[][] PC= {{0x1C8BA2E8BA2D229L,0x2C6E02D934E47EAL,0x3F1BC24C6B68C24L,0x1F88B20DEF08F02L,0x381EDEE3D31D79DL,0x389839C2F47A588L,0x6E08C248L},{0x267DF3F1605FB7BL,0x2DDC7E30A177B32L,0x336003B14866F69L,0x37799E1FE5B542BL,0x1D2565B0DFA7DCCL,0x27381F89CB63B02L,0x10321DA07L},{0x3241067BE390C9EL,0x242CBB700C9DE5FL,0x14BAF4BB1B7FA31L,0x200E83172659D8CL,0x15D138F22DD2ECBL,0x2F3E9F10B830DD4L,0x169B1F8E1L},{0x171986A8497E317L,0xA57CA5ADD3A55BL,0x16C928C5D1DE4FAL,0x1B39E7D55D28B16L,0x163BE990DC43B75L,0x269E3F11EE42CCDL,0x80D3CF1FL},{0xCB5618E3F0C88EL,0x1F23E323D1D6BE7L,0x62EF0F2753339BL,0x2AC9D6D36C69A0BL,0xD1117E53356DE5L,0x6AF6F8BA1D0E21L,0x17B81E770L},{0x1D7F225A139ED84L,0x944A30414BB2B7L,0x2218F9C86B2A8DAL,0x993C3E33864023L,0x38AE652BFB11586L,0x3F9134A5A8DC9B0L,0xD6ED6553L},{0x113C1C66F652983L,0x1C34B72B9CF4673L,0x2B9097E68F90A08L,0x1F76549E66E7B4EL,0x3F7A74AB5DB3CB1L,0x35CC4FFC0744806L,0x1630C3250L},{0x1154CE9AC8895D9L,0x28A1BCC079DF114L,0x2B65982FAC18985L,0x168495FECFC21BBL,0x3E4118E5499DB99L,0x667D10D990AD2CL,0xE99726A3L},{0x1B388641D9B6861L,0x1B89738C41C64F1L,0x3289F1B33083533L,0x195AA36FC97C6CCL,0x307E55412D7F5E4L,0x3F31B6DD3818274L,0x1778E7166L},{0x179F9DAC9EDCB0L,0x30F8F4A825CA7F8L,0x2501EC68E25C958L,0x1CCA5660F95A1E3L,0x1D10A9A1BCE0324L,0x25D9E3B07441231L,0xD54005DBL},{0x34EEF1B3CB83BBL,0x23CA9BCC630D5BAL,0x233C70D1E86B483L,0x16CBDAA105FD597L,0x22147A81C7C17E7L,0x250EACBC1622EACL,0x17294ED3EL},{0x2AC1662734649B7L,0x30B57CB98B5BABL,0x3B56CDB4E2C8561L,0x2228B5C017FC989L,0x1D99815856B303EL,0x3A0CCD02E024407L,0x11A05F2B1L},{0x16384D168ECDD0AL,0x1D392D2DE19400BL,0x133978F31C15931L,0x3BA5BDF40DDDB7DL,0x2B3A56680F682B4L,0x27A4AB511DB5B8FL,0x95FC13ABL},{0x376EC3A79A1D641L,0x99A4AAEE90DC11L,0xDA67F398835038L,0x75C584D9ADD040L,0x1AFC7A3CCE07F8DL,0x36953E097A482CFL,0xA10ECF6AL},{0x1F7D99BBDCC5A5EL,0x16E52274478B4C4L,0x21CDF9822C580FAL,0x3086F29A2A0665BL,0x74CF01996E7F63L,0x3592A2C8C2CFD6CL,0x14A7AC2A9L},{0x2574496EE84A3AL,0xECD4E3C3781B3BL,0x73062AEDE9CEA7L,0x266BD4E862538B8L,0x3E0596721570F57L,0x5A4D8643CF8318L,0x772CAACFL},{0x2DF9A29F6304A5L,0x3492F108A3C470L,0x3CEF24B8982F740L,0x3A73A72B534290EL,0x30506C6E9395735L,0x13999EE554E43DFL,0xE7355F8EL},{0x39D395B3532A21EL,0xA6EA07CD5E0754L,0x4E833B306DA9BDL,0x16684818AEE35ADL,0x343E7A07DFFDFC7L,0x8A452A029BC757L,0x13A8E1620L},{0x30DE8938DC62CD8L,0x1B5490FBB3D7104L,0x28ABC28D6FD0497L,0xFC5AC595455332L,0x37C40EB545B0824L,0x162B8BFB20EABFBL,0x3425581AL},{0xC239BA5CB83E19L,0xF4259F253FB73FL,0xE00B11ACEACD6AL,0x1BD69C63347F299L,0x1BFF2991F6F8941L,0x1E8C897A04DF98AL,0xB2962FE5L},{0x1C8276EC82B3BFFL,0x2AA211B2C09BA79L,0x2588C48BF5713DL,0x32833C20030049BL,0x298E536367041E8L,0x2D56710D22D1C44L,0x12561A5DEL},{0x13CF9FA40D21B1CL,0x235A06F8D0F7E26L,0x8617FC8AC62B55L,0x12E8D6D22EA7256L,0x34BD3FA6F01D5EFL,0x33FC66B862CB98BL,0x8CA8D548L},{0xB456BE69C8B604L,0x1409FBFB0071DC1L,0x14FA95AF01B2B66L,0x23E125968E55EB7L,0x342DF2EB5CB181DL,0x243C0F393A942CEL,0x15E6BE4E9L},{0x26B1E715475224BL,0x4126D95E6BEDE1L,0xF5D396A7CE46BAL,0x2075FA195A366ACL,0x348C4A3FC5E673DL,0x39133C440A8567DL,0x5C129645L},{0x2D9D3F5DB980133L,0x3E42B4708CA9910L,0x232D3C40659CC6CL,0x20353056004F99L,0x27BE315DC757B3BL,0x347B2A6DCBF002BL,0x245A394AL},{0x14C04F00B971EF8L,0x214706464847C83L,0x10E807B4633F06CL,0xA8D09AC23B009CL,0x4F53F447AA7B1L,0x6E4E674554258L,0xB182CAC1L},{0x207C8A4D0074D8EL,0x2737D06D13581B3L,0x3E7F911F643249DL,0x2E2ABC30918B9AFL,0x3FED2EDCC523559L,0x3CDBDB7AE463050L,0x18B46A908L},{0x13711AD011C132L,0x3CE97338FEEBF3AL,0x3E416389E61031BL,0x32DB2BD24FF4460L,0x31D43FB93CD2FCBL,0xDF346F837F42E3L,0x19713E479L},{0x3AFAAEBCA731C30L,0x3DC157753AE9BCAL,0x1E7ED1E4D43B9B3L,0x29E456BDBF81A61L,0x3ADA14A23C42A0CL,0x61AF6D488EAF79L,0xE1BBA7A1L},{0x370E577BDBA587L,0x1948071E181E8D8L,0x2E6A1F20CABE69DL,0x599E7709B07A2DL,0x21E4DA1BB8F3ABDL,0x3659A12FA232788L,0x9FC4018BL},{0x15E4CA31870FB29L,0x191543FB7FA4D68L,0xDA6C26C842642FL,0x2FF8EF7607FF40EL,0x12CA6C674170A05L,0xCEAE1BF7A649AFL,0x987C8D53L},{0x161F8855FE9D6F2L,0x21EB09183D057B2L,0x13C4D634F3747AL,0x328AF86132D48C5L,0x27796B3CE75BB8L,0x3EB06EF2CB25DF4L,0x4AB0B9BCL},{0x1B23AB13633A5F0L,0x3D8C9B256A01CA6L,0x1C3D3AD5544E203L,0x352BEB6DEF5D941L,0x1B8F0A6A074A7D0L,0x18D2DA88847847L,0x16603FCA4L},{0x1B6DAECF2E8FEDBL,0x1FE370264102A10L,0x3FD221351ADC2EEL,0x3EF8F3942E1E60CL,0x2A21529C4195536L,0x3F83FC4D72BD3F8L,0x8CC03FDEL},{0x2355C77B0E5F4CBL,0x16AEA7B1877B29L,0x23EC03251CF9DE4L,0x2E43BADE4702792L,0x2D8746757D42AA7L,0x22607085E261D46L,0x1F86376EL},{0xDFE240C72DE1F6L,0x354858A2C0148EEL,0x3E4B91400DA7D26L,0x359628C738B0D12L,0x6A3B49942552E2L,0x2A59B99BD28E132L,0xCC786BAL},{0x97E75A2E41C696L,0x159C4658BEA2FF8L,0x2343EB67AD34D6CL,0x1B0953CE0F43E41L,0x376FB46831223E9L,0x13B960475440DB5L,0x134996A10L},{0x29845719707BB33L,0x31EBBA6CEE8F0AFL,0x2F6C956543D3CD0L,0x23922A1A548AD4AL,0x14980DCFA11AD13L,0x2E893B8096747C2L,0x90D97C81L},{0x15473A1D634B8FL,0xBD5C3C4D25E011L,0x3CD6356CAA205CAL,0x19789CEE14CC93BL,0x20D7819C171C40FL,0x1B7700F9AC90957L,0xE0FA1D81L},{0x1FADC1326ED06F7L,0x145EF61C5332034L,0xDF27942480E420L,0x2539CA49F072DD2L,0x153CD76F2BF565BL,0x2CB93CED8A2F743L,0x2660400EL},{0x299B138573345CCL,0x1D8F8EE42B047L,0x2EF9A00D9B86930L,0x3662B7C0899F573L,0xB45F1496543346L,0x31D9FF8F0D84C51L,0xAD6B9514L},{0x284B529E2561092L,0x25A261BDFAEFAA5L,0x1A88CEA7913516FL,0x22BBF390B4A303EL,0x248C50C477F94FFL,0x20740CFFD614B07L,0xACCBB674L},{0xF8B49CBA8F6AA8L,0x170A7D3E0C18100L,0x1B36E636A5C871AL,0xE6ED8698A43964L,0x1AD2911D9C6DD0L,0x3A9016F523C0428L,0x4D2F259EL},{0x6EF48BB8913F55L,0x217A8F54A6CD78DL,0x192E7EA7D4FBC73L,0x18F84F61EED4C21L,0x3D94A84903216F7L,0x1C29B873AA08165L,0x167A55CDAL},{0x3233D9D55535D4AL,0x3F8BDEEE49220DAL,0x350C4BF39B4852CL,0x3931ABD6482AF15L,0x3D1D74CC4F9FB0CL,0xDB1848C686F953L,0x1866C8ED3L},{0xEE415A15812ED9L,0x3D6C020077B918L,0xFD206357132B92L,0x17BE87D3F5FFACDL,0x2BBA6FF6EE5A437L,0x38FA9FA80EF377EL,0x16A3EF08BL},{0x11A1399126A775CL,0x2A7006962C7EE4FL,0x25BC400A0051D5FL,0x3EA3433E3BD774DL,0xACE9824B5EECFDL,0x2A676CBF0EEA1CDL,0x166007C08L},{0x2C6477FAAF9B7ACL,0xE36E77EA733880L,0x187B6F0F5A6449FL,0x3195543620717B3L,0x2AC783182B70152L,0x61B6CB67EC99BAL,0x8D9E5297L},{0x239142311A5001DL,0x2C57703F4BB7B76L,0x1A0FC9DEC916A20L,0x27C3DA6EEC150BBL,0x2F8228DDCC6D19CL,0x117D0F92C033244L,0xBE0E0795L},{0xD26D98445F5416L,0xD93CB0A0A5EB6AL,0x2489E726AF41727L,0x36F76F34C3848F6L,0x389EDB4D1D115C5L,0x26394E57C8348EFL,0x16B7D2887L},{0x22538B53DBF67F2L,0x15F358DBE5BE247L,0x25DD279CD2ECA67L,0x15546B9FCC430D6L,0x16E8EB15778C485L,0x1903689DBEAAB9FL,0x58DF3306L},{0x2F6102C2E49A03DL,0x10981D8D4A78D4CL,0x356F453E01F78AL,0x3DCC71356729284L,0x43C348B885C84FL,0xE0480786832F5BL,0x1962D75C2L},{0x1479253B03663C1L,0xDA23BD83081B40L,0x232B5BE72E7A07FL,0x395E2602F9BBB0CL,0xFAD0EAE9601A6DL,0x2A7262C94860450L,0x16112C4C3L}};

public static final long[] CURVE_HTPC2= {0x27713A80F8492BL,0x211421FBAA68D1FL,0x361DD4CB6D9723BL,0x1B89D475CD7D27CL,0x21ECE6B49FAD53L,0x301E011E4075923L,0x52988B9L};
public static final long[] CURVE_Adr= {0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Adi= {0xF0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Bdr= {0x3F4L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[] CURVE_Bdi= {0x3F4L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L};
public static final long[][] PCR= {{0xE2AAAAAAAA5ED1L,0x238E343D9C71C62L,0x108F142B8575709L,0x39FD3A042A88B58L,0x11F5FB614CB14B4L,0x28E333EBB5B7A9AL,0x171D6541FL},{0x2A9FFFFFFFFC71EL,0xAAAA72E3555549L,0xC6B4F20A418147L,0x2B7DEB831FE6882L,0x2D787C88F984F87L,0x2EAA66F0C849BF3L,0x11560BF17L},{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x238AAAAAAAA97D6L,0x18E38D0F671C718L,0x423C50AE15D5C2L,0xE7F4E810AA22D6L,0x247D7ED8532C52DL,0x3A38CCFAED6DEA6L,0x5C759507L},{0xCL,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x1B371C71C718B10L,0x2425E95B712F678L,0x37C69AA274524E7L,0xDE87898A1AC3A5L,0x1E3811AD0761B0FL,0x2DB3DE6FEFDC10FL,0x124C9AD43L},{0x2A9FFFFFFFFC71CL,0xAAAA72E3555549L,0xC6B4F20A418147L,0x2B7DEB831FE6882L,0x2D787C88F984F87L,0x2EAA66F0C849BF3L,0x11560BF17L},{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x2CFC71C71C6D706L,0x3097AFE324BDA04L,0x39D87D27E500FC8L,0x35281FD926FD510L,0x3076D11930F7DA5L,0x2AD044ED6693062L,0x1530477C7L},{0x12L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x1FEFFFFFFFFA8FBL,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L}};
public static final long[][] PCI= {{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x354FFFFFFFFE38DL,0x255553971AAAAA4L,0x635A790520C0A3L,0x35BEF5C18FF3441L,0x36BC3E447CC27C3L,0x375533786424DF9L,0x8AB05F8BL},{0x2A9FFFFFFFFC71AL,0xAAAA72E3555549L,0xC6B4F20A418147L,0x2B7DEB831FE6882L,0x2D787C88F984F87L,0x2EAA66F0C849BF3L,0x11560BF17L},{0x238AAAAAAAA97D6L,0x18E38D0F671C718L,0x423C50AE15D5C2L,0xE7F4E810AA22D6L,0x247D7ED8532C52DL,0x3A38CCFAED6DEA6L,0x5C759507L},{0x1FEFFFFFFFFAA9FL,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L},{0x1FEFFFFFFFFAA63L,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L},{0x0L,0x0L,0x0L,0x0L,0x0L,0x0L,0x0L},{0x354FFFFFFFFE38FL,0x255553971AAAAA4L,0x635A790520C0A3L,0x35BEF5C18FF3441L,0x36BC3E447CC27C3L,0x375533786424DF9L,0x8AB05F8BL},{0x238AAAAAAAA97BEL,0x18E38D0F671C718L,0x423C50AE15D5C2L,0xE7F4E810AA22D6L,0x247D7ED8532C52DL,0x3A38CCFAED6DEA6L,0x5C759507L},{0x2CFC71C71C6D706L,0x3097AFE324BDA04L,0x39D87D27E500FC8L,0x35281FD926FD510L,0x3076D11930F7DA5L,0x2AD044ED6693062L,0x1530477C7L},{0x1FEFFFFFFFFAA99L,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L},{0x1FEFFFFFFFFA9D3L,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L},{0x1FEFFFFFFFFA8FBL,0x2FFFFAC54FFFFEEL,0x12A0F6B0F6241EAL,0x213CE144AFD9CC3L,0x2434BACD764774BL,0x25FF9A692C6E9EDL,0x1A0111EA3L}};

}

