<?php

namespace OpsWay\OneLogin\Helper;

use \Magento\Framework\App\Helper\AbstractHelper;
use \Magento\Store\Model\ScopeInterface;
use \Magento\Framework\App\Helper\Context;
use \Magento\Framework\Module\Dir\Reader;
use \Magento\Framework\UrlInterface;

class Data extends AbstractHelper
{
    const ONELOGIN_METADATA_BASE = 'https://app.onelogin.com/saml/metadata/';
    const ONELOGIN_SSO_BASE = 'https://app.onelogin.com/trust/saml2/http-post/sso/';
    const ONELOGIN_SLO_BASE = 'https://app.onelogin.com/trust/saml2/http-redirect/slo/';

    /**
     * @var UrlInterface
     */
    protected $urlInterface;

    /**
     * @var Reader
     */
    protected $reader;

    public function __construct(
        Context $context,
        Reader $reader,
        array $data = []
    )
    {
        $this->urlInterface = $context->getUrlBuilder();
        $this->reader = $reader;
        parent::__construct($context);
    }

    public function getSettings()
    {
        $currentUrl = $this->getCurrentUrl();
        $adminUrl = $this->getUrl('admin');
        if (stripos($currentUrl, $adminUrl) === false) {
            $currentUrl = $adminUrl;
        }
        $appId = $this->getConfig("dev/onelogin/app_id");
        return array (
            'strict' => false,
            'debug' => false,
            'sp' => array (
                'entityId' => 'php-saml',
                'assertionConsumerService' => array (
                    'url' => $currentUrl,
                ),
                'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
            ),
            'idp' => array (
                'entityId' => self::ONELOGIN_METADATA_BASE.$appId,
                'singleSignOnService' => array (
                    'url' => self::ONELOGIN_SSO_BASE.$appId,
                ),
                'singleLogoutService' => array (
                    'url' => self::ONELOGIN_SLO_BASE.$appId,
                ),
                'x509cert' => $this->getConfig('dev/onelogin/certificate'),
            ),
            'security' => array (
                'signMetadata' => false,
                'nameIdEncrypted' => false,
                'authnRequestsSigned' => false,
                'logoutRequestSigned' => false,
                'logoutResponseSigned' => false,
                'wantMessagesSigned' => false,
                'wantAssertionsSigned' => false,
                'wantAssertionsEncrypted' => false,
            )
        );
    }

    public function getModuleDir() {
        return $this->reader->getModuleDir('', $this->_getModuleName());
    }

    public function getConfig($config_path)
    {
        return $this->scopeConfig->getValue(
            $config_path,
            ScopeInterface::SCOPE_STORE
        );
    }

    public function getCurrentUrl()
    {
        return $this->urlInterface->getCurrentUrl();
    }

    public function getUrl($route, $params = [])
    {
        return $this->urlInterface->getUrl($route,$params);
    }

    public function getOneLoginUrl()
    {
        $SAMLsettings = new \OneLogin_Saml2_Settings(
            $this->getSettings()
        );
        $idpData = $SAMLsettings->getIdPData();
        $idpSSO = '';
        if (isset($idpData['singleSignOnService']) && isset($idpData['singleSignOnService']['url'])) {
            $idpSSO = $idpData['singleSignOnService']['url'];
            $authnRequest = new \OneLogin_Saml2_AuthnRequest($SAMLsettings);
            $parameters['SAMLRequest'] = $authnRequest->getRequest();
            $idpSSO = \OneLogin_Saml2_Utils::redirect($idpSSO, $parameters, true);
        }
        return $idpSSO;
    }

}