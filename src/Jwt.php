<?php
/**
 * Created by PhpStorm.
 * User: liyuzhao
 * Date: 2019-08-01
 * Time: 11:43
 */

namespace Phper666\JwtAuth;

use Lcobucci\JWT\Token;
use Phper666\JwtAuth\Exception\TokenValidException;
use Phper666\JwtAuth\Exception\JWTException;
use Phper666\JwtAuth\Traits\CommonTrait;
use Hyperf\Di\Annotation\Inject;
/**
 * https://github.com/phper666/jwt-auth
 * @author LI Yuzhao <562405704@qq.com>
 */
class Jwt
{
    use CommonTrait;

    /**
     * @Inject
     * @var Blacklist
     */
    protected $blacklist;

    /**
     * 生成token
     * @param array $claims
     * @param bool $isInsertSsoBlack 是否把单点登录生成的token加入黑名单
     * @return Token
     */
    public function getToken(array $claims, $isInsertSsoBlack = true)
    {
        if ($this->loginType == 'mpop') { // 多点登录
            $uniqid = uniqid();
        } else { // 单点登录
            if (empty($claims[$this->ssoKey])) {
                throw new JWTException("There is no {$this->ssoKey} key in the claims", 500);
            }
            $uniqid = $claims[$this->ssoKey];
        }

        $signer = new $this->supportedAlgs[$this->alg];
        $now = new \DateTimeImmutable();
        $ttl = $this->ttl;
        $builder = $this->getBuilder()
            ->identifiedBy($uniqid) // 设置jwt的jti
            ->issuedAt($now)// (iat claim) 发布时间
            ->canOnlyBeUsedAfter($now)// (nbf claim) 在此之前不可用
            ->expiresAt($now->modify("+$ttl second" ));// (exp claim) 到期时间

        foreach ($claims as $k => $v) {
            $builder = $builder->withClaim($k, $v); // 自定义数据
        }

        $token = $builder->getToken($signer, $this->getKey()); // Retrieves the generated token

        if ($isInsertSsoBlack) {
            $this->blacklist->add($token);
        }

        return $token; // 返回的是token对象，使用强转换会自动转换成token字符串。Token对象采用了__toString魔术方法
    }

    /**
     * 刷新token
     *
     * @param string|null $token
     * @return Token
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function refreshToken($token)
    {
        if (is_null($token) || $token === '') {
            if (!($token = $this->getHeaderToken())) {
                throw new JWTException('A token is required', 500);
            }
        }
        $tokenObj = $this->getTokenObj($token);

        if(!$this->blacklist->isNotExpire($tokenObj)){
            throw new TokenValidException('Token authentication does not pass', 401);
        }

//        $claims = $this->blacklist->add($tokenObj);
        $claims = $this->claimsToArray($tokenObj->getClaims());
        unset($claims['iat']);
        unset($claims['nbf']);
        unset($claims['exp']);
        unset($claims['jti']);
        return $this->getToken($claims);
    }

    /**
     * 让token失效
     *
     * @param string|null $token
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function logout($token=null)
    {
        $token = $this->getTokenObj($token);
        $claims = $this->claimsToArray($token->getClaims());
        $this->blacklist->remove($claims['jti']);
        return true;
    }

    /**
     * 验证token
     * @param string $token JWT
     * @return true
     * @throws \Throwable
     */
    public function checkToken($validate = true, $verify = true, $token=null)
    {
        try {
            $token = $this->getTokenObj($token);
        } catch (\RuntimeException $e) {
            throw new \RuntimeException($e->getMessage(), $e->getCode(), $e->getPrevious());
        }

        if (!$this->blacklist->isNotExpire($token)) {
            throw new TokenValidException('Token authentication does not pass', 401);
        }

        if ($this->enalbed) {
            $claims = $this->claimsToArray($token->getClaims());
            $verify_code = $this->blacklist->has($claims);
            if ($verify_code !== 1) {
                throw new TokenValidException('Token authentication does not pass', $verify_code);
            }
        }

        if ($validate && !$this->validateToken($token)) {
            throw new TokenValidException('Token authentication does not pass', 401);
        }
        if ($verify && !$this->verifyToken($token)) {
            throw new TokenValidException('Token authentication does not pass', 401);
        }
        
        return true;
     }

    /**
     * 获取Token token
     * @param $token
     * @param int $dynamicCacheTime
     * @return string|null
     */
    public function getTokenObj($token = null)
    {
        if(is_null($token) || $token === ''){
            $token = $this->getHeaderToken();
        }
        return $this->getParser()->parse($token);
     }

    /**
     * 获取token的过期剩余时间，单位为s
     * @return int|mixed
     */
    public function getTokenDynamicCacheTime()
    {
        $nowTime = time();
        $exp = $this->getTokenObj()->getClaim('exp', $nowTime);
        $expTime = $exp - $nowTime;
        return $expTime;
    }

    /**
     * 获取jwt token解析的dataç
     * @return array
     */
    public function getParserData()
    {
        $arr = [];
        $claims = $this->getTokenObj()->getClaims();
        foreach ($claims as $k => $v) {
            $arr[$k] = $v->getValue();
        }
        return $arr;
    }
}
