<?php

namespace OpsWay\OneLogin\Block;

use Magento\Framework\View\Element\Template as BaseBlock;
use OpsWay\OneLogin\Helper\Data;
use Magento\Framework\View\Element\Template\Context;

class OneLoginLinkBlock extends BaseBlock {

    /**
     * @var Data
     */
    public $helper;

    public function __construct(Context $context, Data $helper, array $data = [])
    {
        $this->helper = $helper;
        parent::__construct($context, $data);
    }

}