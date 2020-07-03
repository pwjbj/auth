<?php
/**
 * Created by PhpStorm.
 * User: liyuzhao
 * Date: 2019-08-06
 * Time: 16:02
 */

namespace Phper666\JwtAuth;

use Hyperf\Di\Annotation\AbstractAnnotation;
use Lcobucci\JWT\Token;
use Phper666\JwtAuth\Helper\Utils;
use Phper666\JwtAuth\Traits\CommonTrait;

/**
 * https://github.com/phper666/jwt-auth
 * author LI Yuzhao <562405704@qq.com>
 */
class Blacklist extends AbstractAnnotation
{
    use CommonTrait;

    /**
     * 把token加入到黑名单中
     * @return $claims
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function add(Token $token)
    {
        $claims = $this->claimsToArray($token->getClaims());
        $jti = $claims['jti'];
        $iat = $claims['iat'];
        if ($this->enalbed) {
            $this->storage->set(
                $jti,
                ['valid_until' => $iat],
                $this->getSecondsUntilExpired($claims)
            );
        }

        return $claims;
    }

    /**
     * Get the number of seconds until the token expiry.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     *
     * @return int
     */
    protected function getSecondsUntilExpired($claims)
    {
        $exp = Utils::timestamp($claims['exp']);
        $iat = Utils::timestamp($claims['iat']);

        // get the latter of the two expiration dates and find
        // the number of minutes until the expiration date,
        // plus 1 minute to avoid overlap
        return $exp->max($iat->addSeconds($this->cacheTTL))->addSecond()->diffInSeconds();
    }

    /**
     * Get the timestamp when the blacklist comes into effect
     * This defaults to immediate (0 seconds).
     *
     * @return int
     */
    protected function getGraceTimestamp()
    {
        if ($this->loginType == 'sso') $this->gracePeriod = 0;
        return Utils::now()->addSeconds($this->gracePeriod)->getTimestamp();
    }

    /**
     * 判断token是否已经加入黑名单
     * @param $claims
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function has($claims)
    {
        if ($this->enalbed && $this->loginType == 'mpop') {
            // check whether the expiry + grace has past
            return !$this->storage->has($claims['jti']);
        }

        if ($this->enalbed && $this->loginType == 'sso') {
            $val = $this->storage->get($claims['jti']);
            if(empty($val)){
                return true;
            }
            // 这里为什么要大于等于0，因为在刷新token时，缓存时间跟签发时间可能一致，详细请看刷新token方法
            $isFuture = ($claims['iat'] - $val['valid_until']) >= 0;
            // check whether the expiry + grace has past
            return !$isFuture;
        }

        return false;
    }

    /**
     * 判断黑名单是否有效
     *
     * @param Token $token
     * @return bool ture 未过期 false过期
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function isNotExpire(Token $token)
    {
        $claims = $this->claimsToArray($token->getClaims());
        return $this->storage->has($claims['jti']);
    }

    /**
     * 黑名单移除token
     * @param $jwtJti
     * @return bool
     * @throws \Psr\SimpleCache\InvalidArgumentException
     */
    public function remove($jwtJti)
    {
        return $this->storage->delete($jwtJti);
    }

    /**
     * 移除所有的缓存，注意：这样会把系统所有的缓存都清掉 todo
     * @return bool
     */
    public function clear()
    {
        $this->storage->clear();

        return true;
    }

    /**
     * Set the cache time limit.
     *
     * @param  int  $ttl
     *
     * @return $this
     */
    public function setCacheTTL($ttl)
    {
        $this->cacheTTL = (int) $ttl;

        return $this;
    }

    /**
     * Get the cache time limit.
     *
     * @return int
     */
    public function getCacheTTL()
    {
        return $this->cacheTTL;
    }
}
