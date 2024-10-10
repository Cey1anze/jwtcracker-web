import {Card} from "@nextui-org/card";
import {Textarea, Input} from "@nextui-org/input";
import {Select, SelectItem, SelectSection} from "@nextui-org/select";
import {Button} from "@nextui-org/button";

import DefaultLayout from "@/layouts/default";

import { useState } from 'react';
import {jwtDecode, JwtHeader} from 'jwt-decode';
import { KJUR, b64utoutf8 } from 'jsrsasign';

const hashAlgoOption = [
    {value: "HS256", label: "SHA256"},
    {value: "HS384", label: "SHA384"},
    {value: "HS512", label: "SHA512"},
];

export default function IndexPage() {

    const [jwt, setJwt] = useState('');
    const [secretKey, setSecretKey] = useState('');
    const [header, setHeader] = useState('');
    const [payload, setPayload] = useState('');
    const [error, setError] = useState('');
    const [verificationResult, setVerificationResult] = useState('');
    const [jwtInvalid, setJwtInvalid] = useState(false);
    const [keyInvalid, setKeyInvalid] = useState(false);
    const [headerInvalid, setHeaderInvalid] = useState(false);
    const [payloadInvalid, setPayloadInvalid] = useState(false);
    const [algorithm, setAlgorithm] = useState('HS256');

    const cleanState = () => {
        setJwtInvalid(false);
        setKeyInvalid(false);
        setHeaderInvalid(false);
        setPayloadInvalid(false);
        setVerificationResult('');
    }

    const decodeJwt = () => {
        cleanState();

        if (!jwt) {
            setJwtInvalid(true);
            return;
        }
        try {
            const decodedHeader = jwtDecode<JwtHeader>(jwt, { header: true });
            setHeader(JSON.stringify(decodedHeader, null, 2));

            const decodedPayload = jwtDecode(jwt);
            setPayload(JSON.stringify(decodedPayload, null, 2));

            setError('');
        } catch (e) {
            setError('Token 无效，请检查输入');
        }
    };

    const verifyJwt = () => {
        cleanState();

        if (!jwt) {
            setJwtInvalid(true);
        }
        if (!secretKey) {
            setKeyInvalid(true);
        }

        if (!jwt || !secretKey) {
            return;
        }

        try {
            const [headerB64] = jwt.split('.');
            const headerJson = JSON.parse(b64utoutf8(headerB64));
            const alg = headerJson.alg; // 从头部获取签名算法

            const isValid = KJUR.jws.JWS.verify(jwt, secretKey, [alg]);
            setVerificationResult(isValid ? "校验成功" : "校验失败");
        } catch (e) {
            setVerificationResult("校验过程中出错");
        }
    };

    const encodeJwt = () => {
        cleanState();

        if (!secretKey) {
            setKeyInvalid(true);
        }
        if (!header) {
            setHeaderInvalid(true);
        }
        if (!payload) {
            setPayloadInvalid(true);
        }

        if (!secretKey || !header || !payload) {
            return;
        }

        try {
            // 使用 jsrsasign 编码 JWT
            const jwtToken = KJUR.jws.JWS.sign(algorithm, JSON.stringify(JSON.parse(header)), JSON.stringify(JSON.parse(payload)), secretKey);
            setJwt(jwtToken);
            setError('');
        } catch (e) {
            setError('编码过程中出错，请检查输入');
        }
    };

    return (
        <DefaultLayout>
            <section className="flex items-center justify-center">
                <Card className="md:w-[90%] lg:w-[90%] border-none p-4" isBlurred shadow={"lg"}>
                    <div className={"card-container"}>
                        <Textarea
                            fullWidth
                            variant="bordered"
                            label="Token"
                            labelPlacement="outside"
                            placeholder="输入 Token"
                            className="justify-center p-4"
                            value={jwt}
                            onChange={(e) => setJwt(e.target.value)}
                            isInvalid={jwtInvalid}
                            errorMessage={jwtInvalid ? 'Token 不能为空' : ''}
                        />
                        {error && <div className="text-red-500 p-2">{error}</div>}
                        <Input
                            fullWidth
                            variant="bordered"
                            label="密钥"
                            labelPlacement="outside"
                            placeholder="加解密时输入密钥 / 爆破时预览结果"
                            className="justify-center p-4"
                            value={secretKey}
                            onChange={(e) => setSecretKey(e.target.value)}
                            isInvalid={keyInvalid}
                            errorMessage={keyInvalid ? '密钥不能为空' : ''}
                            description={verificationResult}
                        />
                        <div className="flex justify-center gap-4">
                            <Button color="primary" variant="bordered" className="p-4" onClick={verifyJwt}>
                                校验
                            </Button>
                            <Button color="primary" variant="bordered" className="p-4" onClick={decodeJwt}>
                                解码
                            </Button>
                        </div>
                        <section className="grid grid-cols-1 md:grid-cols-2 gap-4 py-8 md:py-10 p-8">
                            {/* 左侧内容 */}
                            <div className="flex items-start justify-start">
                                <Card className="w-full border-none p-6" isBlurred>
                                    <div className="flex flex-col gap-4">
                                        <h2>密钥爆破</h2>
                                        <div className="flex flex-wrap md:flex-nowrap gap-4 w-full">
                                            {/* 设置 Input 组件占满整个宽度 */}
                                            <Input className="w-full" label="密钥长度" variant="bordered"/>
                                        </div>
                                        <div className="flex w-full flex-wrap md:flex-nowrap gap-4">
                                            {/* 设置 Select 组件占满整个宽度 */}
                                            <Select label="字符集" variant="bordered" className="w-full">
                                                <SelectSection showDivider title="单类型">
                                                    <SelectItem key="abcdefghijklmnopqrstuvwxyz">小写字母</SelectItem>
                                                    <SelectItem key="ABCDEFGHIJKLMNOPQRSTUVWXYZ">大写字母</SelectItem>
                                                    <SelectItem key="0123456789">数字</SelectItem>
                                                </SelectSection>
                                                <SelectSection showDivider title="混合类型">
                                                    <SelectItem
                                                        key="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ">大小写字母</SelectItem>
                                                    <SelectItem
                                                        key="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789">字母+数字</SelectItem>
                                                    <SelectItem
                                                        key="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?/~">
                                                        大小写字母、数字和特殊字符
                                                    </SelectItem>
                                                </SelectSection>
                                                <SelectSection showDivider title="自定义">
                                                    <SelectItem key="custom">自定义</SelectItem>
                                                </SelectSection>
                                            </Select>
                                        </div>
                                        <div className="flex w-full flex-wrap md:flex-nowrap gap-4">
                                            {/* 设置 Input 组件占满整个宽度 */}
                                            <Input className="w-full" label="自定义字符集" variant="bordered"/>
                                        </div>
                                        <Select
                                            label="签名算法"
                                            variant="bordered"
                                            className="w-full"
                                        >
                                            {hashAlgoOption.map((option) => (
                                                <SelectItem key={option.value}>{option.label}</SelectItem>
                                            ))}
                                        </Select>
                                        <Button color="primary" variant="bordered" className="p-4">
                                            爆破
                                        </Button>
                                    </div>
                                </Card>
                            </div>

                            {/* 右侧内容 */}
                            <div className="flex items-start justify-start gap-4">
                                <Card className="w-full h-full border-none p-6" isBlurred>
                                    <div className="flex flex-col gap-4">
                                        <div className="flex w-full flex-wrap md:flex-nowrap gap-4">
                                            <Button color="primary" variant="bordered" className="p-4" onClick={encodeJwt}>
                                                编码
                                            </Button>
                                            <Select
                                                label="签名算法"
                                                variant="bordered"
                                                labelPlacement="outside-left"
                                                className="max-w-xs"
                                                value={algorithm}
                                                onChange={(e) => setAlgorithm(e.target.value)}
                                            >
                                                {hashAlgoOption.map((option) => (
                                                    <SelectItem key={option.value}>{option.label}</SelectItem>
                                                ))}
                                            </Select>
                                        </div>
                                        <Textarea
                                            fullWidth
                                            variant="bordered"
                                            label="头部"
                                            className="justify-center p-4"
                                            value={header}
                                            onChange={(e) => setHeader(e.target.value)}
                                            isInvalid={headerInvalid}
                                            errorMessage={headerInvalid ? '头部不能为空' : ''}
                                        />
                                        <Textarea
                                            fullWidth
                                            variant="bordered"
                                            label="载荷"
                                            className="justify-center p-4"
                                            value={payload}
                                            onChange={(e) => setPayload(e.target.value)}
                                            isInvalid={payloadInvalid}
                                            errorMessage={payloadInvalid ? '载荷不能为空' : ''}
                                        />
                                    </div>
                                </Card>
                            </div>
                        </section>
                    </div>
                </Card>
            </section>
        </DefaultLayout>
    );
}
