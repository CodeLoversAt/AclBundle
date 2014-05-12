<?php
/**
 * @package mymailbuddy
 *
 * @author Daniel Holzmann <d@velopment.at>
 * @date 27.04.14
 * @time 14:46
 */

namespace CodeLovers\AclBundle;

final class Permissions
{
    const PERMISSIONS_IGNORE = 99; // if this permission is passed, we'll create no extra ACL entries, but inherit from parent
    const PERMISSIONS_OWNER = 0;
    const PERMISSIONS_VIEW = 1;
    const PERMISSIONS_EDIT = 2;

    private function __construct() {}
}