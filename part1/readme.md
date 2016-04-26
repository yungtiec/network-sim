# OpenFlow applications using MININET and POX controller - part 1

Two switches are created using POX API for going throught the following openflow-tutorial 

### 1. Creating a Learning Switch [link to github!](https://github.com/mininet/openflow-tutorial/wiki/Create-a-Learning-Switch)

  of_tutorial.py:
    act_like_switch: modified to simulate layer-2 switch behavior

  To simulate
    - open two console: one for mininet, one for the controller
    - create topology in mininet console (the following two were used)
      ```
      sudo mn --topo single,3 --mac --switch ovsk --controller remote
      ```
      ![Image of single switch topology]
      (https://raw.githubusercontent.com/wiki/mininet/openflow-tutorial/images/Three_switch_layout_simple.png)

      ```
      sudo mn --topo linear --switch ovsk --controller remote
      ```
      ![Image of two-switch topology]
      (https://raw.githubusercontent.com/wiki/mininet/openflow-tutorial/images/Linear2.png)
    - start controller in controller console
      ```
      ./pox py log.level --DEBUG misc.of_tutorial
      ```

### 2. Router Exercise [link to github!](https://github.com/mininet/openflow-tutorial/wiki/Router-Exercise)

  static_router.py
    controller to make a static layer-3 forwarder/switch

  mytopo1.py
    create the following topology
    ![Image to router exercise topology]
    (https://raw.githubusercontent.com/wiki/mininet/openflow-tutorial/images/router_exercise_topo.png)

  To simulate
    To simulate
    - open two console: one for mininet, one for the controller
    - create topology in mininet console
      make sure mytopo1.py is in the mininet directory
      ```
      sudo mn --custom ~/mininet/mytopo1.py --topo mytopo --mac --controller=remote,ip=127.0.0.1
      ```
    - start controller in controller console
      ```
      ./pox py log.level --DEBUG misc.static_router



