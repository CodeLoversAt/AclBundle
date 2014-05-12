<?php
/**
 * @package mymailbuddy
 *
 * @author Daniel Holzmann <d@velopment.at>
 * @date 27.04.14
 * @time 14:42
 */

namespace CodeLovers\AclBundle\Handler;


use CodeLovers\AclBundle\Permissions;
use Symfony\Component\Security\Core\User\UserInterface;

interface AclHandlerInterface
{
    /**
     * @param object $object
     * @param UserInterface $user
     * @param int $permission
     * @param bool $new
     * @param null $parent
     * @return bool
     * @throws \InvalidArgumentException
     */
    public function grantAccess($object, UserInterface $user = null, $permission = Permissions::PERMISSIONS_VIEW, $new = true, $parent = null);

    /**
     * shortcut method
     *
     * @param object $object
     * @param object $parent
     *
     * @return bool
     */
    public function grantInheritedAccess($object, $parent);

    /**
     * delete the ACL for the given object
     *
     * @param object $object
     */
    public function deleteAcl($object);

    /**
     * @param object $object
     * @param UserInterface $user
     * @param int $permission
     *
     * @return AclHandlerInterface
     */
    public function revokeAccess($object, UserInterface $user, $permission = Permissions::PERMISSIONS_VIEW);
}