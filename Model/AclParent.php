<?php
/**
 * @package mymailbuddy
 *
 * @author Daniel Holzmann <d@velopment.at>
 * @date 27.04.14
 * @time 14:48
 */

namespace CodeLovers\AclBundle\Model;


interface AclParent
{
    /**
     * returns an array with the children
     * on which grantInheritedAccess() should be called
     * afterwards
     *
     * @return \Traversable
     */
    public function getAclChildren();
}