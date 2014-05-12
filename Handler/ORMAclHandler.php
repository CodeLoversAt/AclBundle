<?php
/**
 * @package AclBundle
 *
 * @author Daniel Holzmann <d@velopment.at>
 * @date 12.05.14
 * @time 11:58
 */

namespace CodeLovers\AclBundle\Handler;


class ORMAclHandler extends AbstractAclHandler
{
    const PROXY_CLASS_NAME = 'Doctrine\ORM\Proxy\Proxy';

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