<?php

namespace OpsWay\OneLogin\Observer;

use Magento\Framework\Event\ObserverInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Event\Observer;
use Magento\Backend\Model\Auth\Session;
use OpsWay\OneLogin\Helper\Data;
use Magento\User\Model\UserFactory;
use Magento\Framework\Exception\AuthenticationException;
use Magento\Framework\Message\ManagerInterface as MessageManager;
use \Magento\Framework\Event\ManagerInterface as EventManager;
use \Magento\Framework\Registry;
use \Magento\Security\Model\AdminSessionsManager;
use \Magento\Framework\Stdlib\DateTime\DateTime;

/**
 * Class OneLoginObserver
 * @package OpsWay\OneLogin\Observer
 * @todo Replace using of deprecated method \Magento\Framework\Model\AbstractModel:load()
 */
class OneLoginObserver implements ObserverInterface
{
    /**
     * @var Data
     */
    protected $helper;

    /**
     * @var RequestInterface
     */
    protected $request;

    /**
     * @var Session
     */
    protected $session;

    /**
     * @var UserFactory
     */
    protected $userFactory;

    /**
     * @var MessageManager
     */
    protected $messageManager;

    /**
     * @var Registry
     */
    protected $registry;

    /**
     * @var EventManager
     */
    protected $eventManager;

    /**
     * @var AdminSessionsManager
     */
    protected $adminSessionsManager;

    /**
     * @var DateTime
     */
    private $dateTime;

    public function __construct(
        Data $helper,
        Session $session,
        RequestInterface $request,
        UserFactory $userFactory,
        MessageManager $messageManager,
        Registry $registry,
        EventManager $eventManager,
        AdminSessionsManager $adminSessionsManager,
        DateTime $dateTime
    ) {
        $this->helper = $helper;
        $this->session = $session;
        $this->request = $request;
        $this->userFactory = $userFactory;
        $this->messageManager = $messageManager;
        $this->registry = $registry;
        $this->eventManager = $eventManager;
        $this->adminSessionsManager = $adminSessionsManager;
        $this->dateTime = $dateTime;
    }

    public function execute(Observer $observer)
    {
        if (null === $this->request->getParam("SAMLResponse") || $this->registry->registry('onelogin_observer_fired')) {
            return;
        }
        $this->registry->register('onelogin_observer_fired',true);
        try {
            $userData = $this->getUserData();
            $user = $this->userFactory->create()->load($userData['email'], 'email');
            if ($user->getId()) {
                if ($user->getIsActive() != '1') {
                    throw new AuthenticationException(
                        __('You did not sign in correctly or your account is temporarily disabled.')
                    );
                }
                if (!$user->hasAssigned2Role($user->getId())) {
                    throw new AuthenticationException(__('You need more permissions to access this.'));
                }
                if ($this->session->isLoggedIn())
                    $this->session->processLogout();
                $this->session->setUser($user);
                $this->adminSessionsManager->getCurrentSession()->load($this->session->getSessionId());
                $sessionInfo = $this->adminSessionsManager->getCurrentSession();
                $sessionInfo->setUpdatedAt($this->dateTime->gmtTimestamp());
                $sessionInfo->setStatus($sessionInfo::LOGGED_IN);
                $this->adminSessionsManager->processLogin();
                $this->eventManager->dispatch(
                    'backend_auth_user_login_success',
                    ['user' => $user]
                );
            } else {
                throw new AuthenticationException(__("User does not exist."));
            }
        } catch (AuthenticationException $e) {
            $this->messageManager->addErrorMessage($e->getMessage());
        } catch (\Exception $e) {
            $this->messageManager->addErrorMessage(__("An error occurred: ") . $e->getMessage());
        }
    }

    private function getUserData() {
        $postSAMLResponse = $this->request->getParam("SAMLResponse");
        $settings = $this->helper->getSettings();
        $SAMLsettings = new \OneLogin_Saml2_Settings($settings);
        $samlResponse = new \OneLogin_Saml2_Response($SAMLsettings, $postSAMLResponse);
        try {
            if ($samlResponse->isValid()) {
                $userData = array();
                if (!empty($attrs)) {
                    $usernameMap = $this->helper->getConfig('dev/onelogin/username');
                    if (isset($attrs[$usernameMap])) {
                        $userData['username'] = $attrs[$usernameMap][0];
                    }
                    $emailMap = $this->helper->getConfig('dev/onelogin/email');
                    if (isset($attrs[$emailMap])) {
                        $userData['email'] = $attrs[$emailMap][0];
                    }

                    $firstNameMap = $this->helper->getConfig('dev/onelogin/firstname');
                    if (isset($attrs[$firstNameMap])) {
                        $userData['first_name'] = $attrs[$firstNameMap][0];
                    }
                    $lastNameMap = $this->helper->getConfig('dev/onelogin/lastname');
                    if (isset($attrs[$lastNameMap])) {
                        $userData['last_name'] = $attrs[$lastNameMap][0];
                    }
                    $roleMap = $this->helper->getConfig('dev/onelogin/role');
                    if (isset($attrs[$roleMap])) {
                        $roles = $attrs[$roleMap];
                        if (!empty($roles)) {
                            $userData['role'] = array();
                            $role1 = $this->helper->getConfig('dev/onelogin/magentorole1');
                            $roleMap1 = explode(',', $this->helper->getConfig('dev/onelogin/magentomapping1'));
                            $role2 = $this->helper->getConfig('dev/onelogin/magentorole2');
                            $roleMap2 = explode(',', $this->helper->getConfig('dev/onelogin/magentomapping2'));
                            $role3 = $this->helper->getConfig('dev/onelogin/magentorole3');
                            $roleMap3 = explode(',', $this->helper->getConfig('dev/onelogin/magentomapping3'));

                            foreach ($roles as $role) {
                                if (in_array($role, $roleMap1)) {
                                    $userData['role'][] = $role1;
                                }
                                if (in_array($role, $roleMap2)) {
                                    $userData['role'][] = $role2;
                                }
                                if (in_array($role, $roleMap3)) {
                                    $userData['role'][] = $role3;
                                }
                            }
                        }
                    }
                }

                if (!isset($userData['email']) || empty($userData['email'])) {
                    $userData['email'] = $samlResponse->getNameId();
                }

                if (!isset($userData['username']) || empty($userData['username'])) {
                    $userData['username'] = $userData['email'];
                }

                if (!isset($userData['first_name']) || empty($userData['first_name'])) {
                    $userData['first_name'] = '.';
                }

                return $userData;
            } else {
                throw new AuthenticationException(__("Invalid SAML response."));
            }
        } catch (AuthenticationException $e) {
            $this->messageManager->addErrorMessage($e->getMessage());
        } catch (\Exception $e) {
            $this->messageManager->addErrorMessage(__("An error occurred: ") . $e->getMessage());
        }
    }
}
