<?php
/**
 * @package mymailbuddy
 *
 * @author Daniel Holzmann <d@velopment.at>
 * @date 27.04.14
 * @time 14:50
 */

namespace CodeLovers\AclBundle\Handler;


class MongoDbAclHandler extends AbstractAclHandler
{
    const PROXY_CLASS_NAME = 'Doctrine\ODM\MongoDB\Proxy\Proxy';

    /**
     * returns the class name of the doctrine proxies
     *
     * @return string
     */
    protected function getProxyClassName()
    {
        return self::PROXY_CLASS_NAME;
    }
}